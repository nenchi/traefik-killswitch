package traefik_killswitch

// A minimal reader for MaxMind DB (.mmdb) files, enough to look up a country code. It works with
// DB-IP Lite Country, MaxMind GeoLite2-Country/City and other files in that format.
// Hand-written instead of a library: plugins run in Yaegi, and the usual readers rely on unsafe/mmap/reflect.
// Spec: https://maxmind.github.io/MaxMind-DB/

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"
)

var mmdbMarker = []byte("\xAB\xCD\xEFMaxMind.com")

type mmdb struct {
	buf        []byte
	nodeCount  int
	recordSize int
	ipVersion  int
	treeSize   int // bytes; the data section starts 16 bytes later
	ipv4Start  int // node reached after 96 zero bits (IPv4 in an IPv6 tree)
}

func parseMMDB(buf []byte) (*mmdb, error) {
	i := bytes.LastIndex(buf, mmdbMarker)
	if i < 0 {
		return nil, errors.New("not a MaxMind DB file (metadata marker missing)")
	}
	meta := i + len(mmdbMarker)
	db := &mmdb{buf: buf}
	d := decoder{buf: buf, base: meta}
	typ, size, off, err := d.ctrl(meta)
	if err != nil {
		return nil, err
	}
	if typ != typeMap {
		return nil, errors.New("metadata is not a map")
	}
	for n := 0; n < size; n++ {
		key, next, err := d.str(off)
		if err != nil {
			return nil, err
		}
		switch key {
		case "node_count", "record_size", "ip_version":
			v, after, err := d.uint(next)
			if err != nil {
				return nil, err
			}
			if key == "node_count" {
				db.nodeCount = int(v)
			} else if key == "record_size" {
				db.recordSize = int(v)
			} else {
				db.ipVersion = int(v)
			}
			off = after
		default:
			after, err := d.skip(next)
			if err != nil {
				return nil, err
			}
			off = after
		}
	}
	if db.recordSize != 24 && db.recordSize != 28 && db.recordSize != 32 {
		return nil, fmt.Errorf("unsupported record size %d", db.recordSize)
	}
	if db.ipVersion != 4 && db.ipVersion != 6 {
		return nil, fmt.Errorf("unsupported ip version %d", db.ipVersion)
	}
	db.treeSize = db.nodeCount * db.recordSize / 4
	if db.nodeCount == 0 || db.treeSize+16 > meta {
		return nil, errors.New("search tree larger than file")
	}
	node := 0
	if db.ipVersion == 6 {
		for n := 0; n < 96 && node < db.nodeCount; n++ {
			node = db.record(node, 0)
		}
	}
	db.ipv4Start = node
	return db, nil
}

// record reads the left (bit 0) or right (bit 1) record of a search tree node.
func (db *mmdb) record(node, bit int) int {
	b := db.buf
	switch db.recordSize {
	case 24:
		o := node*6 + bit*3
		return int(b[o])<<16 | int(b[o+1])<<8 | int(b[o+2])
	case 28:
		o := node * 7
		if bit == 0 {
			return int(b[o+3]&0xF0)<<20 | int(b[o])<<16 | int(b[o+1])<<8 | int(b[o+2])
		}
		return int(b[o+3]&0x0F)<<24 | int(b[o+4])<<16 | int(b[o+5])<<8 | int(b[o+6])
	default:
		o := node*8 + bit*4
		return int(b[o])<<24 | int(b[o+1])<<16 | int(b[o+2])<<8 | int(b[o+3])
	}
}

// country returns the ISO code for ip ("" if the file has no entry): country, else registered_country.
func (db *mmdb) country(ip netip.Addr) string {
	ip = ip.Unmap()
	var addr []byte
	node := 0
	if ip.Is4() {
		a := ip.As4()
		addr = a[:]
		node = db.ipv4Start
	} else {
		if db.ipVersion == 4 {
			return ""
		}
		a := ip.As16()
		addr = a[:]
	}
	for i := 0; i < len(addr)*8 && node < db.nodeCount; i++ {
		node = db.record(node, int(addr[i/8]>>(7-uint(i%8)))&1)
	}
	if node <= db.nodeCount {
		return "" // == nodeCount: no data for this address
	}
	off := db.treeSize + node - db.nodeCount
	if off >= len(db.buf) {
		return ""
	}
	d := decoder{buf: db.buf, base: db.treeSize + 16}
	for _, path := range [][]string{{"country", "iso_code"}, {"registered_country", "iso_code"}} {
		if at, ok := d.find(off, path); ok {
			if s, _, err := d.str(at); err == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

const (
	typePointer = 1
	typeString  = 2
	typeMap     = 7
	typeArray   = 11
	typeBool    = 14
)

// decoder reads the data section; base is where pointers count from.
type decoder struct {
	buf  []byte
	base int
}

var errTruncated = errors.New("mmdb: truncated data")

// ctrl decodes a field's control bytes: type, size (for a pointer: its absolute target) and the payload offset.
func (d decoder) ctrl(off int) (int, int, int, error) {
	if off >= len(d.buf) {
		return 0, 0, 0, errTruncated
	}
	c := int(d.buf[off])
	off++
	typ := c >> 5
	if typ == typePointer {
		ss := (c >> 3) & 3
		n := ss + 1
		if off+n > len(d.buf) {
			return 0, 0, 0, errTruncated
		}
		p := 0
		if ss < 3 {
			p = c & 7
		}
		for j := 0; j < n; j++ {
			p = p<<8 | int(d.buf[off+j])
		}
		switch ss {
		case 1:
			p += 2048
		case 2:
			p += 526336
		}
		return typePointer, d.base + p, off + n, nil
	}
	if typ == 0 { // extended type
		if off >= len(d.buf) {
			return 0, 0, 0, errTruncated
		}
		typ = 7 + int(d.buf[off])
		off++
	}
	size := c & 0x1f
	if size >= 29 {
		n := size - 28
		if off+n > len(d.buf) {
			return 0, 0, 0, errTruncated
		}
		v := 0
		for j := 0; j < n; j++ {
			v = v<<8 | int(d.buf[off+j])
		}
		off += n
		switch n {
		case 1:
			size = 29 + v
		case 2:
			size = 285 + v
		default:
			size = 65821 + v
		}
	}
	return typ, size, off, nil
}

// skip returns the offset after the field at off (a pointer is skipped, not followed).
func (d decoder) skip(off int) (int, error) {
	typ, size, next, err := d.ctrl(off)
	if err != nil {
		return 0, err
	}
	switch typ {
	case typePointer, typeBool:
		return next, nil
	case typeMap, typeArray:
		n := size
		if typ == typeMap {
			n = size * 2
		}
		for j := 0; j < n; j++ {
			next, err = d.skip(next)
			if err != nil {
				return 0, err
			}
		}
		return next, nil
	}
	if next+size > len(d.buf) {
		return 0, errTruncated
	}
	return next + size, nil
}

// str reads a string, following one pointer; the returned offset is after the field itself.
func (d decoder) str(off int) (string, int, error) {
	typ, size, next, err := d.ctrl(off)
	if err != nil {
		return "", 0, err
	}
	if typ == typePointer {
		s, _, err := d.str(size)
		return s, next, err
	}
	if typ != typeString {
		return "", 0, fmt.Errorf("mmdb: want string, got type %d", typ)
	}
	if next+size > len(d.buf) {
		return "", 0, errTruncated
	}
	return string(d.buf[next : next+size]), next + size, nil
}

func (d decoder) uint(off int) (uint64, int, error) {
	typ, size, next, err := d.ctrl(off)
	if err != nil {
		return 0, 0, err
	}
	if typ == typePointer {
		v, _, err := d.uint(size)
		return v, next, err
	}
	if typ != 5 && typ != 6 && typ != 9 || size > 8 || next+size > len(d.buf) {
		return 0, 0, fmt.Errorf("mmdb: want unsigned int, got type %d", typ)
	}
	var v uint64
	for j := 0; j < size; j++ {
		v = v<<8 | uint64(d.buf[next+j])
	}
	return v, next + size, nil
}

// find walks map keys from off and returns the offset of the value at path.
func (d decoder) find(off int, path []string) (int, bool) {
	typ, size, next, err := d.ctrl(off)
	if err != nil {
		return 0, false
	}
	if typ == typePointer {
		return d.find(size, path)
	}
	if len(path) == 0 {
		return off, true
	}
	if typ != typeMap {
		return 0, false
	}
	for j := 0; j < size; j++ {
		key, valOff, err := d.str(next)
		if err != nil {
			return 0, false
		}
		if key == path[0] {
			return d.find(valOff, path[1:])
		}
		next, err = d.skip(valOff)
		if err != nil {
			return 0, false
		}
	}
	return 0, false
}

// ponytail: one open file per path for the whole process; re-checked once a minute, swapped when it changes.
type geoipFile struct {
	mu      sync.Mutex
	db      *mmdb
	mod     time.Time
	size    int64
	checked time.Time
	cache   map[netip.Addr]string
}

var (
	geoipMu    sync.Mutex
	geoipFiles = map[string]*geoipFile{}
)

const geoipCacheMax = 10000 // ponytail: cache cleared when full; an LRU if hit rates ever matter

// lookupGeoIP returns the country for ip from the .mmdb at path, loading and reloading it as needed.
// A missing or broken file logs and returns "", so the unknown policy applies; it never breaks the middleware.
func lookupGeoIP(path string, ip netip.Addr) string {
	geoipMu.Lock()
	f := geoipFiles[path]
	if f == nil {
		f = &geoipFile{cache: map[netip.Addr]string{}}
		geoipFiles[path] = f
	}
	geoipMu.Unlock()

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.db == nil || time.Since(f.checked) > time.Minute {
		f.checked = time.Now()
		fi, err := os.Stat(path)
		if err != nil {
			if f.db == nil {
				log.Printf("killswitch geo: %v", err)
			}
		} else if f.db == nil || !fi.ModTime().Equal(f.mod) || fi.Size() != f.size {
			buf, err := os.ReadFile(path)
			if err == nil {
				db, perr := parseMMDB(buf)
				if perr == nil {
					f.db = db
					f.mod = fi.ModTime()
					f.size = fi.Size()
					f.cache = map[netip.Addr]string{}
					logInfo("geo database %s loaded (%d MB)", path, len(buf)>>20)
				} else {
					err = perr
				}
			}
			if err != nil {
				log.Printf("killswitch geo: %s: %v (keeping previous database)", path, err)
			}
		}
	}
	if f.db == nil {
		return ""
	}
	if c, ok := f.cache[ip]; ok {
		return c
	}
	c := f.db.country(ip)
	if len(f.cache) >= geoipCacheMax {
		f.cache = map[netip.Addr]string{}
	}
	f.cache[ip] = c
	return c
}
