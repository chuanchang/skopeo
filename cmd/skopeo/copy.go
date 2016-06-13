package main

import (
	"encoding/json"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/projectatomic/skopeo/manifest"
	"github.com/projectatomic/skopeo/signature"
)

// FIXME(runcom): put this elsewhere:
// docker.go contains similar code, more sophisticated
// (at the very least the deduplication should be reused from there).
func manifestLayers(manifest []byte) ([]string, error) {
	mt := mutils.GuessMIMEType(manifest)
	layers := []string{}
	switch mt {
	case mutils.DockerV2Schema1MIMEType:
		man := manifestSchema1{}
		if err := json.Unmarshal(manifest, &man); err != nil {
			return nil, err
		}
		for _, layer := range man.FSLayers {
			layers = append(layers, layer.BlobSum)
		}
	case mutils.DockerV2Schema2MIMEType:
		// TODO(runcom): move to its own type!
		v2s2 := struct {
			Config struct {
				Digest string
			}
			Layers []struct {
				// TODO(runcom): handle MediaType also for external URLs
				Digest string `json:"digest"`
			} `json:"layers"`
		}{}
		if err := json.Unmarshal(manifest, &v2s2); err != nil {
			return nil, err
		}
		for _, layer := range v2s2.Layers {
			layers = append(layers, layer.Digest)
		}
	}
	return layers, nil
}

// FIXME: this is a copy from docker_image.go and does not belong here.
type manifestSchema1 struct {
	Name     string
	Tag      string
	FSLayers []struct {
		BlobSum string `json:"blobSum"`
	} `json:"fsLayers"`
	History []struct {
		V1Compatibility string `json:"v1Compatibility"`
	} `json:"history"`
	// TODO(runcom) verify the downloaded manifest
	//Signature []byte `json:"signature"`
}

func copyHandler(context *cli.Context) {
	if len(context.Args()) != 2 {
		logrus.Fatal("Usage: copy source destination")
	}

	src, err := parseImageSource(context, context.Args()[0])
	if err != nil {
		logrus.Fatalf("Error initializing %s: %s", context.Args()[0], err.Error())
	}

	dest, err := parseImageDestination(context, context.Args()[1])
	if err != nil {
		logrus.Fatalf("Error initializing %s: %s", context.Args()[1], err.Error())
	}
	signBy := context.String("sign-by")

	//if OCI image destination, then ask for v2s2 manifest for config

	m, _, err := src.GetManifest([]string{manifest.DockerV2Schema1MIMEType})
	if err != nil {
		logrus.Fatalf("Error reading manifest: %s", err.Error())
	}

	layers, err := manifestLayers(m)
	if err != nil {
		logrus.Fatalf("Error parsing manifest: %s", err.Error())
	}
	for _, layer := range layers {
		// TODO(mitr): do not ignore the size param returned here
		stream, _, err := src.GetBlob(layer)
		if err != nil {
			logrus.Fatalf("Error reading layer %s: %s", layer, err.Error())
		}
		defer stream.Close()
		if err := dest.PutBlob(layer, stream); err != nil {
			logrus.Fatalf("Error writing layer: %s", err.Error())
		}
	}

	sigs, err := src.GetSignatures()
	if err != nil {
		logrus.Fatalf("Error reading signatures: %s", err.Error())
	}

	if signBy != "" {
		mech, err := signature.NewGPGSigningMechanism()
		if err != nil {
			logrus.Fatalf("Error initializing GPG: %s", err.Error())
		}
		dockerReference, err := dest.CanonicalDockerReference()
		if err != nil {
			logrus.Fatalf("Error determining canonical Docker reference: %s", err.Error())
		}

		newSig, err := signature.SignDockerManifest(m, dockerReference, mech, signBy)
		if err != nil {
			logrus.Fatalf("Error creating signature: %s", err.Error())
		}
		sigs = append(sigs, newSig)
	}

	if err := dest.PutSignatures(sigs); err != nil {
		logrus.Fatalf("Error writing signatures: %s", err.Error())
	}

	// FIXME: We need to call PutManifest after PutBlob and PutSignatures. This seems ugly; move to a "set properties" + "commit" model?
	if err := dest.PutManifest(m); err != nil {
		logrus.Fatalf("Error writing manifest: %s", err.Error())
	}
}

var copyCmd = cli.Command{
	Name:   "copy",
	Action: copyHandler,
	// FIXME: Do we need to namespace the GPG aspect?
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "sign-by",
			Usage: "sign the image using a GPG key with the specified fingerprint",
		},
	},
}
