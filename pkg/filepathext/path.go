package filepathext

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// SkipDir is a skip directory error used to tell SymWalk() when to skip a directory
var SkipDir = filepath.SkipDir
var lstat = os.Lstat // for testing

// WalkFunc is the type of the function called for each file or directory
// visited by Walk. The path argument contains the argument to Walk as a
// prefix; that is, if Walk is called with "dir", which is a directory
// containing the file "a", the walk function will be called with argument
// "dir/a". The info argument is the os.FileInfo for the named path.
//
// If there was a problem walking to the file or directory named by path, the
// incoming error will describe the problem and the function can decide how
// to handle that error (and Walk will not descend into that directory). In the
// case of an error, the info argument will be nil. If an error is returned,
// processing stops. The sole exception is when the function returns the special
// value SkipDir. If the function returns SkipDir when invoked on a directory,
// Walk skips the directory's contents entirely. If the function returns SkipDir
// when invoked on a non-directory file, Walk skips the remaining files in the
// containing directory.
type WalkFunc filepath.WalkFunc

// readDirNames reads the directory named by dirname and returns
// a sorted list of directory entries.
func readDirNames(dirname string) ([]string, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// ResolveSymlink returns an absolute path that a symlink points to
func ResolveSymlink(path string) (string, os.FileInfo, error) {
	link, err := os.Readlink(path)
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve symlink: %v", err)
	}

	// best guess make it absolute from the current dir
	if !filepath.IsAbs(link) {
		link = filepath.Join(filepath.Dir(path), link)
	}

	info, err := os.Lstat(link)
	if err != nil {
		return "", nil, fmt.Errorf("failed to lstat symlink: %v", err)
	}

	return link, info, nil
}

// walk recursively descends path, calling walkFn.
func walk(path string, info os.FileInfo, walkFn WalkFunc) error {
	// if it's a symlink, resolve the symlink and use the parent file info
	// ignore updating the path
	if info.Mode()&os.ModeSymlink != 0 {
		var err error
		_, info, err = ResolveSymlink(path)
		if err != nil {
			return walkFn(path, info, err)
		}
	}

	// if this isn't a directory, then we're done walking, call it on the last item
	if !info.IsDir() {
		return walkFn(path, info, nil)
	}

	names, err := readDirNames(path)
	err1 := walkFn(path, info, err)
	// If err != nil, walk can't walk into this directory.
	// err1 != nil means walkFn wants walk to skip this directory or stop walking.
	// Therefore, if one of err and err1 isn't nil, walk will return.
	if err != nil || err1 != nil {
		// The caller's behavior is controlled by the return value, which is decided
		// by walkFn. walkFn may ignore err and return nil.
		// If walkFn returns SkipDir, it will be handled by the caller.
		// So walk should return whatever walkFn returns.
		return err1
	}

	for _, name := range names {
		filename := filepath.Join(path, name)
		fileInfo, err := lstat(filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != SkipDir {
				return err
			}
		} else {
			err = walk(filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

// SymWalk is a symbolic link following version of Walk
// When a symlink is encountered, it is checked to be a directory or not
// it is up to the processor to determine how it should be handled by checking the os.FileInfo stat
func SymWalk(root string, walkFn WalkFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		err = walkFn(root, nil, err)
	} else {
		err = walk(root, info, walkFn)
	}
	if err == SkipDir {
		return nil
	}
	return err
}
