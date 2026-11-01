// Generate public interoperability fixtures with Go's independent sumdb code.
// No private key is emitted in fixture mode. Keygen mode is for ephemeral
// qualification servers and writes a fresh private key directly to a file.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type checkpoint struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
	Note string `json:"note"`
}

type inclusion struct {
	Size  uint64   `json:"size"`
	Index uint64   `json:"index"`
	Entry string   `json:"entry"`
	Path  []string `json:"path"`
}

type consistency struct {
	Old  uint64   `json:"old"`
	New  uint64   `json:"new"`
	Path []string `json:"path"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func encode(hashes []tlog.Hash) []string {
	result := make([]string, 0, len(hashes))
	for _, h := range hashes {
		result = append(result, hex.EncodeToString(h[:]))
	}
	return result
}

func main() {
	output := flag.String("output", "", "Fixture output, or key filename prefix in keygen mode")
	keygen := flag.Bool("keygen", false, "Generate fresh temporary log keys instead of fixtures")
	origin := flag.String("origin", "fixture.test/log", "Checkpoint origin")
	flag.Parse()
	if *output == "" {
		panic("-output is required")
	}
	if *keygen {
		private, public, err := note.GenerateKey(rand.Reader, *origin)
		must(err)
		for suffix, contents := range map[string]string{".private": private, ".public": public} {
			file, err := os.OpenFile(*output+suffix, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			must(err)
			_, err = file.WriteString(contents + "\n")
			must(err)
			must(file.Close())
		}
		return
	}
	// Deliberately reproducible public test material, never used by a service.
	private, public, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x71}, 32)), *origin)
	must(err)
	signer, err := note.NewSigner(private)
	must(err)
	var stored []tlog.Hash
	reader := tlog.HashReaderFunc(func(indices []int64) ([]tlog.Hash, error) {
		result := make([]tlog.Hash, 0, len(indices))
		for _, index := range indices {
			if index < 0 || index >= int64(len(stored)) {
				return nil, fmt.Errorf("invalid fixture hash index")
			}
			result = append(result, stored[index])
		}
		return result, nil
	})
	leaves := make([]string, 513)
	entries := make([][]byte, len(leaves))
	causalRoot := bytes.Repeat([]byte{0x11}, 32)
	opening := bytes.Repeat([]byte{0x22}, 32)
	preimage := append([]byte("attest-causal-root/v1\x00"), opening...)
	preimage = append(preimage, causalRoot...)
	commitment := sha256.Sum256(preimage)
	publicEntry := append([]byte("attest-causal-root/v1\n"), commitment[:]...)
	for index := range leaves {
		entries[index] = []byte(fmt.Sprintf("leaf-%04d", index))
		if index == 0 {
			entries[index] = publicEntry
		}
		leaves[index] = base64.StdEncoding.EncodeToString(entries[index])
		hashes, err := tlog.StoredHashes(int64(index), entries[index], reader)
		must(err)
		stored = append(stored, hashes...)
	}
	sizes := []int64{0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33, 255, 256, 257, 511, 512, 513}
	checkpoints := make([]checkpoint, 0, len(sizes))
	inclusions := make([]inclusion, 0)
	consistencies := make([]consistency, 0)
	tiles := make(map[string]string)
	conflicting := make(map[uint64]string)
	untrusted := make(map[uint64]string)
	otherPrivate, _, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x72}, 32)), *origin)
	must(err)
	otherSigner, err := note.NewSigner(otherPrivate)
	must(err)
	for _, size := range sizes {
		root, err := tlog.TreeHash(size, reader)
		must(err)
		text := fmt.Sprintf("%s\n%d\n%s\n", *origin, size, base64.StdEncoding.EncodeToString(root[:]))
		signed, err := note.Sign(&note.Note{Text: text}, signer)
		must(err)
		checkpoints = append(checkpoints, checkpoint{uint64(size), hex.EncodeToString(root[:]), string(signed)})
		otherSigned, err := note.Sign(&note.Note{Text: text}, otherSigner)
		must(err)
		untrusted[uint64(size)] = string(otherSigned)
		if size > 0 {
			forkRoot := sha256.Sum256([]byte(fmt.Sprintf("conflict-%d", size)))
			forkText := fmt.Sprintf("%s\n%d\n%s\n", *origin, size, base64.StdEncoding.EncodeToString(forkRoot[:]))
			forkNote, err := note.Sign(&note.Note{Text: forkText}, signer)
			must(err)
			conflicting[uint64(size)] = string(forkNote)
		}
		if size == 0 {
			continue
		}
		seen := make(map[int64]bool)
		for _, index := range []int64{0, 1, size / 2, size - 1, 254, 255, 256} {
			if index < 0 || index >= size || seen[index] {
				continue
			}
			seen[index] = true
			path, err := tlog.ProveRecord(size, index, reader)
			must(err)
			must(tlog.CheckRecord(path, size, root, index, tlog.RecordHash(entries[index])))
			inclusions = append(inclusions, inclusion{uint64(size), uint64(index), leaves[index], encode(path)})
		}
		seen = make(map[int64]bool)
		for _, old := range []int64{0, 1, 2, size / 2, size - 1, size, 255, 256} {
			if old < 0 || old > size || seen[old] {
				continue
			}
			seen[old] = true
			path := tlog.TreeProof{}
			if old > 0 {
				path, err = tlog.ProveTree(size, old, reader)
				must(err)
				oldRoot, err := tlog.TreeHash(old, reader)
				must(err)
				must(tlog.CheckTree(path, size, root, old, oldRoot))
			}
			consistencies = append(consistencies, consistency{uint64(old), uint64(size), encode(path)})
		}
		for level := 0; size>>(8*level) > 0; level++ {
			nodes := size >> (8 * level)
			for index := int64(0); index*256 < nodes; index++ {
				width := int(nodes - index*256)
				if width > 256 {
					width = 256
				}
				tile := tlog.Tile{H: 8, L: level, N: index, W: width}
				data, err := tlog.ReadTileData(tile, reader)
				must(err)
				// C2SP fixes height eight and therefore omits that path element.
				path := strings.Replace(tile.Path(), "tile/8/", "tile/", 1)
				encoded := hex.EncodeToString(data)
				if previous, ok := tiles[path]; ok && previous != encoded {
					panic("reference library changed an immutable tile")
				}
				tiles[path] = encoded
			}
		}
	}
	// Every prefix used by a proof needs an independently calculated root.
	roots := make(map[uint64]string)
	for size := int64(0); size <= 513; size++ {
		root, err := tlog.TreeHash(size, reader)
		must(err)
		roots[uint64(size)] = hex.EncodeToString(root[:])
	}
	data := map[string]any{
		"format":    "attest-publication-test/v1",
		"generator": "golang.org/x/mod/sumdb/{note,tlog}@v0.42.0",
		"config":    map[string]string{"format": "attest-log/v1", "origin": *origin, "verifier_key": public},
		"leaves":    leaves, "roots": roots, "checkpoints": checkpoints,
		"inclusion": inclusions, "consistency": consistencies, "tiles": tiles,
		"opening":     map[string]string{"causal_root": hex.EncodeToString(causalRoot), "nonce": hex.EncodeToString(opening), "entry": hex.EncodeToString(publicEntry)},
		"conflicting": conflicting, "untrusted": untrusted,
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	must(err)
	must(os.WriteFile(*output, append(encoded, '\n'), 0644))
}
