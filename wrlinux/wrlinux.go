/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/araddon/dateparse"
	"golang.org/x/xerrors"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cveTrackerDir = "windriver-cve-tracker"
	windriverDir  = "wrlinux"
)

var (
	repoURLs = []string{
		"https://distro.windriver.com/git/windriver-cve-tracker.git",
	}
	targets = []string{
		"active",
	}
	statuses = []string{
		"released",
		"pending",
		"not-affected",
		"ignored",
	}
)

type Vulnerability struct {
	Candidate         string
	PublicDate        time.Time
	Description       string
	References        []string
	Notes             []string
	Priority          string
	Bugs              []string
	Patches           map[Package]Statuses
}

type Package string

type Release string

type Statuses map[Release]Status

type Status struct {
	Status string
	Note   string
}

func Update() error {
	var err error
	gc := git.Config{}
	dir := filepath.Join(utils.CacheDir(), cveTrackerDir)
	for _, url := range repoURLs {
		_, err = gc.CloneOrPull(url, dir, "master", false)
		if err == nil {
			break
		}
		log.Printf("failed to clone or pull: %s: %v", url, err)
		log.Printf("removing %s directory", cveTrackerDir)
		if err := os.RemoveAll(dir); err != nil {
			return xerrors.Errorf("failed to remove %s directory: %w", cveTrackerDir, err)
		}
	}
	if err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}

	dst := filepath.Join(utils.VulnListDir(), windriverDir)
	log.Printf("removing windriver directory %s", dst)
	if err := os.RemoveAll(dst); err != nil {
		return xerrors.Errorf("failed to remove windriver directory: %w", err)
	}

	log.Println("walking windriver-cve-tracker ...")
	for _, target := range targets {
		if err := walkDir(filepath.Join(dir, target)); err != nil {
			return err
		}
	}

	return nil
}

func walkDir(root string) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if !strings.HasPrefix(base, "CVE-") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("error in file open: %w", err)
		}

		vuln, err := parse(f)
		if err != nil {
			return xerrors.Errorf("error in parse: %w", err)
		}

		if err = utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), windriverDir), vuln.Candidate, vuln); err != nil {
			return xerrors.Errorf("error in save: %w", err)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("error in walk: %w", err)
	}
	return nil
}

func parse(r io.Reader) (vuln *Vulnerability, err error) {
	vuln = &Vulnerability{}
	vuln.Patches = map[Package]Statuses{}

	all, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(all), "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Skip
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Parse Candidate
		if strings.HasPrefix(line, "Candidate:") {
			line = strings.TrimPrefix(line, "Candidate:")
			vuln.Candidate = strings.TrimSpace(line)
			continue
		}

		// Parse PublicDate
		if strings.HasPrefix(line, "PublicDate:") {
			line = strings.TrimPrefix(line, "PublicDate:")
			line = strings.TrimSpace(line)
			vuln.PublicDate, _ = dateparse.ParseAny(line)
			continue
		}

		// Parse Description
		if strings.HasPrefix(line, "Description:") {
			var description []string
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				description = append(description, line)
			}
			vuln.Description = strings.Join(description, " ")
			continue
		}

		// Parse References
		if strings.HasPrefix(line, "References:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				vuln.References = append(vuln.References, line)
			}
			continue
		}

		// Parse Notes
		if strings.HasPrefix(line, "Notes:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				note := []string{line}
				for strings.HasPrefix(lines[i+1], "  ") {
					i++
					l := strings.TrimSpace(lines[i])
					note = append(note, l)
				}
				vuln.Notes = append(vuln.Notes, strings.Join(note, " "))
			}
			continue
		}

		// Parse Priority
		if strings.HasPrefix(line, "Priority:") {
			line = strings.TrimPrefix(line, "Priority:")
			vuln.Priority = strings.TrimSpace(line)
			continue
		}

		// Parse Bugs
		if strings.HasPrefix(line, "Bugs:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				vuln.Bugs = append(vuln.Bugs, line)
			}
			continue
		}

		// Parse Patches
		// e.g. trusty/esm_vnc4: needs-triage
		s := strings.SplitN(line, ":", 2)
		if len(s) < 2 {
			continue
		}

		status := strings.TrimSpace(s[1])

		// Some advisories have status with "Patches_" prefix and it should be skipped
		// e.g. Patches_qtwebkit-opensource-src: needs-triage
		if isPatch(status) && !strings.HasPrefix(s[0], "Patches_") {
			pkgRel := strings.SplitN(s[0], "_", 2)
			release := Release(pkgRel[0])
			pkgName := Package(strings.Trim(pkgRel[1], ":"))

			fields := strings.Fields(status)
			status := Status{
				Status: fields[0],
			}
			if len(fields) > 1 {
				note := strings.Join(fields[1:], " ")
				status.Note = strings.Trim(note, "()")
			}

			if existingStatuses, ok := vuln.Patches[pkgName]; ok {
				existingStatuses[release] = status
				vuln.Patches[pkgName] = existingStatuses
			} else {
				statuses := Statuses{}
				statuses[release] = status
				vuln.Patches[pkgName] = statuses
			}
		}
	}
	return vuln, nil
}

func isPatch(s string) bool {
	for _, status := range statuses {
		if strings.HasPrefix(s, status) {
			return true
		}
	}
	return false
}
