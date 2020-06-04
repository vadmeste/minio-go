// +build ignore

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/minio/minio-go/v7"
)

func main() {
	s3Client, err := minio.New("s3.amazonaws.com", "", "", false)
	if err != nil {
		log.Fatalln(err)
	}

	// Enable trace.
	// s3Client.TraceOn(os.Stderr)

	bucketName := "vadmeste-testbucket"
	objectName := "testobject"
	origData := []byte("test-content")

	n, err := s3Client.PutObject(context.Background(), bucketName, objectName, bytes.NewReader(origData), int64(len(origData)), minio.PutObjectOptions{})
	if err != nil {
		log.Fatalln("put object:", err)
	}

	if n < int64(len(origData)) {
		log.Fatalln("put object: unexpected uploaded length")
	}

	// Source object
	src := minio.NewSourceInfo(bucketName, objectName, nil)
	dst, err := minio.NewDestinationInfo(bucketName, objectName+"-copy", nil, nil)
	if err != nil {
		log.Fatalln("new dest info:", err)
	}

	// Initiate copy object.
	err = s3Client.CopyObject(context.Background(), dst, src)
	if err != nil {
		log.Fatalln("copy object:", err)
	}

	copyReader, err := s3Client.GetObject(context.Background(), bucketName, objectName+"-copy", minio.GetObjectOptions{})
	if err != nil {
		log.Fatalln("get object:", err)
	}

	copyData, err := ioutil.ReadAll(copyReader)
	if err != nil {
		log.Fatalln("read all:", err)
	}

	fmt.Printf("equal? %v\n", bytes.Equal(origData, copyData))
}
