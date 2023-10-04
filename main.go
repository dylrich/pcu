package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"
)

const (
	// TODO: look up dynamically
	pagesize = 4096

	SYS_CACHESTAT = 451

	usage = `Usage: pcu [OPTIONS] [PATH]

Retrieve page cache usage statistics

OPTIONS:
	-h, -help
		Print this message

	-summarize=<METHOD>
		Set the unit of aggregation

		Valid methods include:

			file
				All individual files will have their statistics reported

			directory[=<DEPTH>]
				Only directories will have their aggregate statistics
				reported. An optional integer depth parameter can be set
				that limits reporting to directories above a certain depth.
				For example, if we're examining a filepath ./abc/123/def/456
				and we set -summarize=directory=2, only ./abc and ./abc/123
				will have statistics reported.
				
			total
				Only the total sum of all files at the current path will be
				reported

	-format=<FORMAT>
		Set the statistics format

		Valid formats include:

			count

				All numbers are reported in terms of page count
				
			-size

				All numbers are reported in terms of their size in bytes

	-human-readable
		When format=size, print sizes in easier to read format
	`
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := newFlagSet("pcu")

	var format string
	var summarize string
	var readable bool

	flags.StringVar(&format, "format", "count", "")
	flags.StringVar(&summarize, "summarize", "file", "")
	flags.BoolVar(&readable, "human-readable", true, "")

	ok, err := parse(flags, args, stderr)
	if err != nil {
		return fmt.Errorf("parse args: %w", err)
	}

	if !ok {
		return nil
	}

	pargs := flags.Args()

	if err := checkKernelVersion(); err != nil {
		return fmt.Errorf("check kernel version: %w", err)
	}

	var root string

	if len(pargs) == 0 {
		root = "."
	} else {
		root = pargs[0]
	}

	info, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	tw := tabwriter.NewWriter(stdout, 10, 0, 4, ' ', 0)

	fmt.Fprintln(tw, "Path\tCache\tDirty\tWriteback\tEvicted\tRecently Evicted")
	fmt.Fprintln(tw, "\t\t\t\t\t")

	var cstatprint printFunc

	switch format {
	case "size":
		if readable {
			cstatprint = makePrettyPrintSize(tw)
		} else {
			cstatprint = makePrintSize(tw)
		}
	default:
		cstatprint = makePrintCount(tw)
	}

	var printdepth int

	if strings.HasPrefix(summarize, "directory") {
		parts := strings.SplitN(summarize, "=", 2)

		summarize = parts[0]

		if len(parts) == 2 {
			n, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return fmt.Errorf("parse print depth")
			}

			printdepth = int(n)
		}
	}

	w := &walker{
		summarize:  summarize,
		printdepth: printdepth,
		print:      cstatprint,
	}

	if _, err := w.walk(root, &statDirEntry{info: info}, 0); err != nil {
		return fmt.Errorf("process: %w", err)
	}

	tw.Flush()

	return nil
}

func readDir(dirname string) ([]fs.DirEntry, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	dirs, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Slice(dirs, func(i, j int) bool {
		if dirs[i].IsDir() == dirs[j].IsDir() {
			return dirs[i].Name() < dirs[j].Name()
		}

		if dirs[i].IsDir() {
			return false
		}

		return true
	})
	return dirs, nil
}

type walker struct {
	summarize  string
	printdepth int
	print      printFunc
}

func (w *walker) walk(path string, d fs.DirEntry, depth int) (*Cachestats, error) {
	info, err := d.Info()
	if err != nil {
		return nil, fmt.Errorf("dir info: %w", err)
	}

	size := info.Size()

	if !d.IsDir() {
		if !d.Type().IsRegular() {
			return &Cachestats{}, nil
		}

		csr := &CachestatRange{
			Off: 0,
			Len: uint64(size),
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open file: %w", err)
		}

		fd := f.Fd()

		var cstat Cachestats

		if err := Cachestat(fd, csr, &cstat, 0); err != nil {
			return nil, fmt.Errorf("cachestat: %w", err)
		}

		f.Close()

		if w.summarize == "file" {
			w.print(cstat, path)
		}

		return &cstat, nil
	}

	dirs, err := readDir(path)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var cstats Cachestats
	for _, d1 := range dirs {
		next := filepath.Join(path, d1.Name())
		cstat, err := w.walk(next, d1, depth+1)
		if err != nil {
			return nil, err
		}

		cstats.Cache += cstat.Cache
		cstats.Dirty += cstat.Dirty
		cstats.Writeback += cstat.Writeback
		cstats.Evicted += cstat.Evicted
		cstats.RecentlyEvicted += cstat.RecentlyEvicted
	}

	switch w.summarize {
	case "file":
		w.print(cstats, path)
	case "directory":
		switch {
		case w.printdepth > 0 && depth <= w.printdepth:
			w.print(cstats, path)
		case w.printdepth == 0:
			w.print(cstats, path)
		}
	case "total":
		if depth == 0 {
			w.print(cstats, path)
		}
	}

	return &cstats, nil

}

type statDirEntry struct {
	info fs.FileInfo
}

func (d *statDirEntry) Name() string               { return d.info.Name() }
func (d *statDirEntry) IsDir() bool                { return d.info.IsDir() }
func (d *statDirEntry) Type() fs.FileMode          { return d.info.Mode().Type() }
func (d *statDirEntry) Info() (fs.FileInfo, error) { return d.info, nil }

func parseuts(data [65]int8) string {
	b := make([]byte, 0, 65)

	for _, v := range data {
		if v == 0 {
			break
		}

		b = append(b, byte(v))
	}

	return string(b[:])
}

func formatBytes(size uint64) string {
	const (
		bb = 1 << (10 * iota)
		kb
		mb
		gb
		tb
	)

	unit := "B"
	value := size

	switch {
	case size >= tb:
		unit = "TB"
		value = value / tb
	case size >= gb:
		unit = "GB"
		value = value / gb
	case size >= mb:
		unit = "MB"
		value = value / mb
	case size >= kb:
		unit = "KB"
		value = value / kb
	}

	v := strings.TrimSuffix(strconv.FormatFloat(float64(value), 'f', 1, 64), ".0")

	return fmt.Sprintf("%s%s", v, unit)
}

func checkKernelVersion() error {
	// TODO: just check for ENOSYS instead of all this junk to check version?
	var utsname syscall.Utsname

	if err := syscall.Uname(&utsname); err != nil {
		return fmt.Errorf("uname: %w", err)
	}

	kernel := parseuts(utsname.Release)

	mmp := strings.SplitN(kernel, "-", 2)
	if len(mmp) != 2 {
		return fmt.Errorf("malformed kernel version string '%s'", kernel)
	}

	parts := strings.SplitN(mmp[0], ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("malformed major.minor.patch '%s'", mmp)
	}

	major, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("parse major version: %w", err)
	}

	minor, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return fmt.Errorf("parse minor version: %w", err)
	}

	if !(major >= 6 && minor >= 5) {
		return fmt.Errorf("your kernel version (%d.%d) does not support the cachestat syscall (6.5+)", major, minor)
	}

	return nil
}

type printFunc func(cstat Cachestats, path string)

func makePrintCount(w io.Writer) printFunc {
	return func(cstat Cachestats, path string) {
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\n", path, cstat.Cache, cstat.Dirty, cstat.Writeback, cstat.Evicted, cstat.RecentlyEvicted)
	}
}

func makePrettyPrintSize(w io.Writer) printFunc {
	return func(cstat Cachestats, path string) {
		cache := formatBytes(cstat.Cache * pagesize)
		dirty := formatBytes(cstat.Dirty * pagesize)
		writeback := formatBytes(cstat.Writeback * pagesize)
		evicted := formatBytes(cstat.Evicted * pagesize)
		recently := formatBytes(cstat.RecentlyEvicted * pagesize)

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", path, cache, dirty, writeback, evicted, recently)
	}
}

func makePrintSize(w io.Writer) printFunc {
	return func(cstat Cachestats, path string) {
		cache := cstat.Cache * pagesize
		dirty := cstat.Dirty * pagesize
		writeback := cstat.Writeback * pagesize
		evicted := cstat.Evicted * pagesize
		recently := cstat.RecentlyEvicted * pagesize

		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%d\t%d\n", path, cache, dirty, writeback, evicted, recently)
	}
}

type CachestatRange struct {
	Off uint64
	Len uint64
}

type Cachestats struct {
	Cache           uint64
	Dirty           uint64
	Writeback       uint64
	Evicted         uint64
	RecentlyEvicted uint64
}

func Cachestat(fd uintptr, cstatrange *CachestatRange, cstat *Cachestats, flags uint) error {
	_, _, e1 := syscall.RawSyscall6(SYS_CACHESTAT, fd, uintptr(unsafe.Pointer(cstatrange)), uintptr(unsafe.Pointer(cstat)), uintptr(flags), 0, 0)
	if e1 != 0 {
		return fmt.Errorf("errno %s", e1)
	}

	return nil
}

func newFlagSet(prog string) *flag.FlagSet {
	f := flag.NewFlagSet(prog, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.Usage = nil

	return f
}

func parse(flags *flag.FlagSet, args []string, stderr io.Writer) (bool, error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, usage)
			return false, nil
		}

		return false, fmt.Errorf("argument parsing failure: %w\n\n%s", err, usage)
	}

	return true, nil
}
