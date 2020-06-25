/*
 * MinIO Go Library for Amazon S3 Compatible Cloud Storage
 * Copyright 2017, 2018 MinIO, Inc.
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
	"context"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// CopyObject - copy a source object into a new object
func (c Client) CopyObject(ctx context.Context, dst DestinationOptions, src SourceOptions) (UploadInfo, error) {
	return c.CopyObjectWithProgress(ctx, dst, src, nil)
}

// CopyObjectWithProgress is like CopyObject with additional progress bar.
func (c Client) CopyObjectWithProgress(ctx context.Context, dst DestinationOptions, src SourceOptions, progress io.Reader) (UploadInfo, error) {
	header := make(http.Header)
	for k, v := range src.Headers {
		header[k] = v
	}

	if dst.opts.ReplaceTags && len(dst.opts.UserTags) != 0 {
		header.Set(amzTaggingHeaderDirective, "REPLACE")
		header.Set(amzTaggingHeader, s3utils.TagEncode(dst.opts.UserTags))
	}

	if dst.opts.LegalHold != LegalHoldStatus("") {
		header.Set(amzLegalHoldHeader, dst.opts.LegalHold.String())
	}

	if dst.opts.Mode != RetentionMode("") && !dst.opts.RetainUntilDate.IsZero() {
		header.Set(amzLockMode, dst.opts.Mode.String())
		header.Set(amzLockRetainUntil, dst.opts.RetainUntilDate.Format(time.RFC3339))
	}

	var err error
	var size int64
	// If progress bar is specified, size should be requested as well initiate a StatObject request.
	if progress != nil {
		size, _, _, err = src.getProps(c)
		if err != nil {
			return UploadInfo{}, err
		}
	}

	if src.encryption != nil {
		encrypt.SSECopy(src.encryption).Marshal(header)
	}

	if dst.opts.ServerSideEncryption != nil {
		dst.opts.ServerSideEncryption.Marshal(header)
	}
	for k, v := range dst.getUserMetaHeadersMap(true) {
		header.Set(k, v)
	}

	resp, err := c.executeMethod(ctx, "PUT", requestMetadata{
		bucketName:   dst.bucket,
		objectName:   dst.object,
		customHeader: header,
	})
	if err != nil {
		return UploadInfo{}, err
	}
	defer closeResponse(resp)

	if resp.StatusCode != http.StatusOK {
		return UploadInfo{}, httpRespToErrorResponse(resp, dst.bucket, dst.object)
	}

	// Update the progress properly after successful copy.
	if progress != nil {
		io.CopyN(ioutil.Discard, progress, size)
	}

	return UploadInfo{
		Bucket:    dst.bucket,
		Key:       dst.object,
		VersionID: resp.Header.Get("x-amz-version-id"),
		ETag:      trimEtag(resp.Header.Get("ETag")),
		opts:      dst.ToOptions(),
	}, nil
}
