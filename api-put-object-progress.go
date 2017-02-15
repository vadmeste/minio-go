/*
 * Minio Go Library for Amazon S3 Compatible Cloud Storage (C) 2015 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package minio

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/minio/minio-go/pkg/s3utils"
)

// PutObjectWithProgress - with progress.
func (c Client) PutObjectWithProgress(bucketName, objectName string, reader io.Reader, contentType string, progress io.Reader) (n int64, err error) {
	metaData := make(map[string][]string)
	metaData["Content-Type"] = []string{contentType}
	return c.PutObjectWithMetadata(bucketName, objectName, reader, metaData, progress)
}

// PutSecureObject - Encrypt and store object.
func (c Client) PutSecuredObject(bucketName, objectName string, reader io.Reader, encKey EncryptionKey, metaData map[string][]string, progress io.Reader) (n int64, err error) {

	// Generate random content key
	randContentKey := make([]byte, aes.BlockSize*2)
	if _, err = rand.Read(randContentKey); err != nil {
		return 0, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return 0, err
	}

	// Build CBC encrypted based on the random content key
	encContentBlock, err := aes.NewCipher(randContentKey)
	if err != nil {
		return 0, err
	}
	mode := cipher.NewCBCEncrypter(encContentBlock, iv)

	// Start to stream encrypted data to pass to the standard PutObject()
	out, in := io.Pipe()

	go func() {
		plainPart := make([]byte, aes.BlockSize)
		cipherPart := make([]byte, aes.BlockSize)

		var pErr, rErr, wErr error
		var n int

		for {
			// Read plain data
			if n, rErr = io.ReadFull(reader, plainPart); rErr != nil && rErr != io.EOF && rErr != io.ErrUnexpectedEOF {
				in.CloseWithError(err)
				return
			}

			// Pad data if this is the last part
			if n < aes.BlockSize {
				if plainPart, pErr = pkcs5Pad(plainPart[:n], aes.BlockSize); pErr != nil {
					in.CloseWithError(pErr)
					return
				}
			}

			// Crypt data
			mode.CryptBlocks(cipherPart, plainPart)

			// Write crypted data to the pipe
			if _, wErr = in.Write(cipherPart); wErr != nil {
				in.CloseWithError(wErr)
				return
			}

			// Quit if we are at the end of the stream
			if n == 0 || (n > 0 && (rErr == io.EOF || rErr == io.ErrUnexpectedEOF)) {
				break
			}
		}
		in.Close()
	}()

	if metaData == nil {
		metaData = make(map[string][]string)
	}

	// Encrypt content key
	encryptedKey, err := encKey.Encrypt(randContentKey)
	if err != nil {
		return 0, err
	}

	metaData[AmzHeaderMatDesc] = []string{"{}"}
	metaData[AmzHeaderIV] = []string{base64.StdEncoding.EncodeToString(iv)}
	metaData[AmzHeaderKey] = []string{base64.StdEncoding.EncodeToString(encryptedKey)}

	return c.PutObjectWithMetadata(bucketName, objectName, out, metaData, progress)
}

// PutObjectWithMetadata - with metadata.
func (c Client) PutObjectWithMetadata(bucketName, objectName string, reader io.Reader, metaData map[string][]string, progress io.Reader) (n int64, err error) {
	// Input validation.
	if err := isValidBucketName(bucketName); err != nil {
		return 0, err
	}
	if err := isValidObjectName(objectName); err != nil {
		return 0, err
	}
	if reader == nil {
		return 0, ErrInvalidArgument("Input reader is invalid, cannot be nil.")
	}

	// Size of the object.
	var size int64

	// Get reader size.
	size, err = getReaderSize(reader)
	if err != nil {
		return 0, err
	}

	// Check for largest object size allowed.
	if size > int64(maxMultipartPutObjectSize) {
		return 0, ErrEntityTooLarge(size, maxMultipartPutObjectSize, bucketName, objectName)
	}

	// NOTE: Google Cloud Storage does not implement Amazon S3 Compatible multipart PUT.
	// So we fall back to single PUT operation with the maximum limit of 5GiB.
	if s3utils.IsGoogleEndpoint(c.endpointURL) {
		if size <= -1 {
			return 0, ErrorResponse{
				Code:       "NotImplemented",
				Message:    "Content-Length cannot be negative for file uploads to Google Cloud Storage.",
				Key:        objectName,
				BucketName: bucketName,
			}
		}
		if size > maxSinglePutObjectSize {
			return 0, ErrEntityTooLarge(size, maxSinglePutObjectSize, bucketName, objectName)
		}
		// Do not compute MD5 for Google Cloud Storage. Uploads up to 5GiB in size.
		return c.putObjectNoChecksum(bucketName, objectName, reader, size, metaData, progress)
	}

	// NOTE: S3 doesn't allow anonymous multipart requests.
	if s3utils.IsAmazonEndpoint(c.endpointURL) && c.anonymous {
		if size <= -1 {
			return 0, ErrorResponse{
				Code:       "NotImplemented",
				Message:    "Content-Length cannot be negative for anonymous requests.",
				Key:        objectName,
				BucketName: bucketName,
			}
		}
		if size > maxSinglePutObjectSize {
			return 0, ErrEntityTooLarge(size, maxSinglePutObjectSize, bucketName, objectName)
		}
		// Do not compute MD5 for anonymous requests to Amazon
		// S3. Uploads up to 5GiB in size.
		return c.putObjectNoChecksum(bucketName, objectName, reader, size, metaData, progress)
	}

	// putSmall object.
	if size < minPartSize && size >= 0 {
		return c.putObjectSingle(bucketName, objectName, reader, size, metaData, progress)
	}
	// For all sizes greater than 5MiB do multipart.
	n, err = c.putObjectMultipart(bucketName, objectName, reader, size, metaData, progress)
	if err != nil {
		errResp := ToErrorResponse(err)
		// Verify if multipart functionality is not available, if not
		// fall back to single PutObject operation.
		if errResp.Code == "AccessDenied" && strings.Contains(errResp.Message, "Access Denied") {
			// Verify if size of reader is greater than '5GiB'.
			if size > maxSinglePutObjectSize {
				return 0, ErrEntityTooLarge(size, maxSinglePutObjectSize, bucketName, objectName)
			}
			// Fall back to uploading as single PutObject operation.
			return c.putObjectSingle(bucketName, objectName, reader, size, metaData, progress)
		}
		return n, err
	}
	return n, nil
}
