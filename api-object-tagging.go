/*
 * MinIO Go Library for Amazon S3 Compatible Cloud Storage
 * Copyright 2020 MinIO, Inc.
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
	"bytes"
	"context"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/minio/minio-go/v7/pkg/s3utils"
	"github.com/minio/minio-go/v7/pkg/tags"
)

type PutObjectTaggingOptions struct {
	VersionID string
}

// PutObjectTagging replaces or creates object tag(s)
func (c Client) PutObjectTagging(ctx context.Context, bucketName, objectName string, objectTags map[string]string, opts PutObjectTaggingOptions) error {
	// Input validation.
	if err := s3utils.CheckValidBucketName(bucketName); err != nil {
		return err
	}

	// Get resources properly escaped and lined up before
	// using them in http request.
	urlValues := make(url.Values)
	urlValues.Set("tagging", "")

	if opts.VersionID != "" {
		urlValues.Set("versionId", opts.VersionID)
	}

	tags, err := tags.NewTags(objectTags, true)
	if err != nil {
		return err
	}

	reqBytes, err := xml.Marshal(tags)
	if err != nil {
		return err
	}

	reqMetadata := requestMetadata{
		bucketName:       bucketName,
		objectName:       objectName,
		queryValues:      urlValues,
		contentBody:      bytes.NewReader(reqBytes),
		contentLength:    int64(len(reqBytes)),
		contentMD5Base64: sumMD5Base64(reqBytes),
	}

	// Execute PUT to set a object tagging.
	resp, err := c.executeMethod(ctx, "PUT", reqMetadata)
	defer closeResponse(resp)
	if err != nil {
		return err
	}
	if resp != nil {
		if resp.StatusCode != http.StatusOK {
			return httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}
	return nil
}

type GetObjectTaggingOptions struct {
	VersionID string
}

// GetObjectTagging fetches object tag(s)
func (c Client) GetObjectTagging(ctx context.Context, bucketName, objectName string, opts GetObjectTaggingOptions) (string, error) {
	// Get resources properly escaped and lined up before
	// using them in http request.
	urlValues := make(url.Values)
	urlValues.Set("tagging", "")

	if opts.VersionID != "" {
		urlValues.Set("versionId", opts.VersionID)
	}

	// Execute GET on object to get object tag(s)
	resp, err := c.executeMethod(ctx, "GET", requestMetadata{
		bucketName:  bucketName,
		objectName:  objectName,
		queryValues: urlValues,
	})

	defer closeResponse(resp)
	if err != nil {
		return "", err
	}

	if resp != nil {
		if resp.StatusCode != http.StatusOK {
			return "", httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}

	tagBuf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(tagBuf), err
}

type RemoveObjectTaggingOptions struct {
	VersionID string
}

// RemoveObjectTagging deletes object tag(s)
func (c Client) RemoveObjectTagging(ctx context.Context, bucketName, objectName string, opts RemoveObjectTaggingOptions) error {
	// Get resources properly escaped and lined up before
	// using them in http request.
	urlValues := make(url.Values)
	urlValues.Set("tagging", "")

	if opts.VersionID != "" {
		urlValues.Set("versionId", opts.VersionID)
	}

	// Execute DELETE on object to remove object tag(s)
	resp, err := c.executeMethod(ctx, "DELETE", requestMetadata{
		bucketName:  bucketName,
		objectName:  objectName,
		queryValues: urlValues,
	})

	defer closeResponse(resp)
	if err != nil {
		return err
	}

	if resp != nil {
		// S3 returns "204 No content" after Object tag deletion.
		if resp.StatusCode != http.StatusNoContent {
			return httpRespToErrorResponse(resp, bucketName, objectName)
		}
	}
	return err
}
