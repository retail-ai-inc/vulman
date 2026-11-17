package main

import (
	"bytes"
	"image/png"
	"log"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: %s <icon.png> <output directory>", os.Args[0])
	}
	if err := writeResources(os.Args[1], os.Args[2]); err != nil {
		log.Fatal(err)
	}
}

func writeResources(iconPath, outputDir string) error {
	data, err := os.ReadFile(iconPath)
	if err != nil {
		return err
	}
	image, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	icon, err := winres.NewIconFromResizedImage(image, nil)
	if err != nil {
		return err
	}
	var resources winres.ResourceSet
	// Wails loads the application's window icon from resource group 3.
	if err := resources.SetIcon(winres.ID(3), icon); err != nil {
		return err
	}
	for _, arch := range []winres.Arch{winres.ArchAMD64, winres.ArchARM64} {
		var object bytes.Buffer
		if err := resources.WriteObject(&object, arch); err != nil {
			return err
		}
		name := "icon_windows_" + string(arch) + ".syso"
		if err := os.WriteFile(filepath.Join(outputDir, name), object.Bytes(), 0644); err != nil {
			return err
		}
	}
	return nil
}
