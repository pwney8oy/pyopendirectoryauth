/*
 *  OpenDirectoryAuth.c
 *  OpenDirectoryAuth
 *
 *  Created by Matteo Pillon <matteo.pillon@gmail.com> on 11/08/09.
 *
 */

#include "OpenDirectoryAuth.h"

/*
 Contains code from http://devworld.apple.com/samplecode/CryptNoMore/
 
 File:       CryptNoMore.c
 
 Contains:   Examples of crypt authentication replacement.
 
 Written by: DTS
 
 Copyright:  Copyright (c) 2008 Apple Inc. All Rights Reserved.
 
 Disclaimer: IMPORTANT: This Apple software is supplied to you by Apple Inc.
 ("Apple") in consideration of your agreement to the following
 terms, and your use, installation, modification or
 redistribution of this Apple software constitutes acceptance of
 these terms.  If you do not agree with these terms, please do
 not use, install, modify or redistribute this Apple software.
 
 In consideration of your agreement to abide by the following
 terms, and subject to these terms, Apple grants you a personal,
 non-exclusive license, under Apple's copyrights in this
 original Apple software (the "Apple Software"), to use,
 reproduce, modify and redistribute the Apple Software, with or
 without modifications, in source and/or binary forms; provided
 that if you redistribute the Apple Software in its entirety and
 without modifications, you must retain this notice and the
 following text and disclaimers in all such redistributions of
 the Apple Software. Neither the name, trademarks, service marks
 or logos of Apple Inc. may be used to endorse or promote
 products derived from the Apple Software without specific prior
 written permission from Apple.  Except as expressly stated in
 this notice, no other rights or licenses, express or implied,
 are granted by Apple herein, including but not limited to any
 patent rights that may be infringed by your derivative works or
 by other works in which the Apple Software may be incorporated.
 
 The Apple Software is provided by Apple on an "AS IS" basis. 
 APPLE MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING
 WITHOUT LIMITATION THE IMPLIED WARRANTIES OF NON-INFRINGEMENT,
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
 THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN
 COMBINATION WITH YOUR PRODUCTS.
 
 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT,
 INCIDENTAL OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING IN ANY WAY
 OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION
 OF THE APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY
 OF CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR
 OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE POSSIBILITY OF
 SUCH DAMAGE.
 
 */

/////////////////////////////////////////////////////////////////
#pragma mark ***** Open Directory (Directory Services)

#include <DirectoryService/DirectoryService.h>

// ***** Parameters

// Set gOpenDirectoryAllowLocalUsersOnly to search only the local 
// node when authenticating.  That is, we'll only authenticate 
// users stored in on the local machine's directory and won't 
// consider users accessible via the authentication search 
// path, such as LDAP and Active Directory entries.

static Boolean gOpenDirectoryAllowLocalUsersOnly = false;

// Set TEST_BUFFER_DOUBLING to 1 to test the buffer doubling 
// functionality (see DoubleTheBufferSizeIfItsTooSmall).

#define TEST_BUFFER_DOUBLING 0
#if TEST_BUFFER_DOUBLING
enum {
	kDefaultDSBufferSize = 1
};
#else
enum {
	kDefaultDSBufferSize = 1024
};
#endif

// ***** Open Directory Utility Routines

static tDirStatus dsDataBufferAppendData(
										 tDataBufferPtr  buf, 
										 const void *    dataPtr, 
										 size_t          dataLen
										 )
// Appends a value to a data buffer.  dataPtr and dataLen describe 
// the value to append.  buf is the data buffer to which it's added.
{
    tDirStatus      err;
	
    assert(buf != NULL);
    assert(dataPtr != NULL);
    assert(buf->fBufferLength <= buf->fBufferSize);
    
    // The cast to size_t in the following line is unnecessary, but it helps 
    // to emphasise that we do this range check in 64-bit if size_t is 64-bit. 
    // Thus, this check will work even if you try to add more than 32-bits of 
    // data to a buffer (which is inherently limited to 32-bits because 
    // fBufferSize is UInt32).
    
    if ( (buf->fBufferLength + dataLen) > (size_t) buf->fBufferSize ) {
        err = eDSBufferTooSmall;
    } else {
        memcpy(&buf->fBufferData[buf->fBufferLength], dataPtr, dataLen);
        buf->fBufferLength += (UInt32) dataLen;
        err = eDSNoErr;
    }
    
    return err;
}

static tDirStatus dsDataListAndHeaderDeallocate(
												tDirReference   inDirReference,
												tDataListPtr    inDataList
												)
// dsDataListDeallocate deallocates the list contents but /not/ the 
// list header (because the list header could be allocated on the 
// stack).  This routine is a wrapper that deallocates both.  It's 
// the logical opposite of the various list allocation routines 
// (for example, dsBuildFromPath).
{
    tDirStatus  err;
    
    assert(inDirReference != 0);
    assert(inDataList != NULL);
    
    err = dsDataListDeallocate(inDirReference, inDataList);
    if (err == eDSNoErr) {
        free(inDataList);
    }
    
    return err;
}

static void DoubleTheBufferSizeIfItsTooSmall(
											 tDirStatus *        errPtr, 
											 tDirNodeReference   dirRef, 
											 tDataBufferPtr *    bufPtrPtr
											 )
// This routine is designed to handle the case where a 
// Open Directory routine returns eDSBufferTooSmall.  
// If so, it doubles the size of the buffer, allowing the 
// caller to retry the Open Directory routine with the 
// large buffer.
//
// errPtr is a pointer to a Open Directory error.  
// This routine does nothing unless that error is 
// eDSBufferTooSmall.  In that case it frees the buffer 
// referenced by *bufPtrPtr, replacing it with a buffer 
// of twice the size.  It then leaves *errPtr set to 
// eDSBufferTooSmall so that the caller retries the 
// call with the larger buffer.
{
    tDirStatus      err;
    tDirStatus      junk;
    tDataBufferPtr  tmpBuf;
    
    assert(errPtr != NULL);
    assert(dirRef != 0);
    assert( bufPtrPtr != NULL);
    assert(*bufPtrPtr != NULL);
    
    if (*errPtr == eDSBufferTooSmall) {
        // If the buffer size is already bigger than 16 MB, don't try to 
        // double it again; something has gone horribly wrong.
        
        err = eDSNoErr;
        if ( (*bufPtrPtr)->fBufferSize >= (16 * 1024 * 1024) ) {
            err = eDSAllocationFailed;
        }
        
        if (err == eDSNoErr) {
            tmpBuf = dsDataBufferAllocate(dirRef, (*bufPtrPtr)->fBufferSize * 2);
            if (tmpBuf == NULL) {
                err = eDSAllocationFailed;
            } else {
#if TEST_BUFFER_DOUBLING
				fprintf(stderr, "Doubled buffer size to %lu.\n", tmpBuf->fBufferSize);
#endif
                
                junk = dsDataBufferDeAllocate(dirRef, *bufPtrPtr);
                assert(junk == eDSNoErr);
                
                *bufPtrPtr = tmpBuf;
            }
        }
		
        // If err is eDSNoErr, the buffer expansion was successful 
        // so we leave *errPtr set to eDSBufferTooSmall.  If err 
        // is any other value, the expansion failed and we set 
        // *errPtr to that error.
        
        if (err != eDSNoErr) {
            *errPtr = err;
        }
    }
}

static tDirStatus dsFindDirNodesQ(
								  tDirReference       inDirReference,
								  tDataBufferPtr *    inOutDataBufferPtrPtr,
								  tDataListPtr        inNodeNamePattern,
								  tDirPatternMatch    inPatternMatchType,
								  UInt32              *outDirNodeCount,
								  tContextData        *inOutContinueData
								  )
// A wrapper for dsFindDirNodes that handles two special cases:
//
// o If the routine returns eDSBufferTooSmall, it doubles the 
//   size of the buffer referenced by *inOutDataBufferPtrPtr 
//   and retries.
//
//   Note that this change requires a change of the function 
//   prototype; the second parameter is a pointer to a pointer 
//   to the buffer, rather than just a pointer to the buffer. 
//   This is so that I can modify the client's buffer pointer.
//
// o If the routine returns no nodes but there's valid continue data, 
//   it retries.
//
// In other respects this works just like dsFindDirNodes.
{
    tDirStatus  err;
    
    // I only supply pre-conditions for the parameters that I touch.
    assert( inOutDataBufferPtrPtr != NULL);
    assert(*inOutDataBufferPtrPtr != NULL);
    assert(outDirNodeCount != NULL);
    assert(inOutContinueData != NULL);
    
    do {
        do {
            err = dsFindDirNodes(
								 inDirReference, 
								 *inOutDataBufferPtrPtr, 
								 inNodeNamePattern, 
								 inPatternMatchType, 
								 outDirNodeCount, 
								 inOutContinueData
								 );
            DoubleTheBufferSizeIfItsTooSmall(&err, inDirReference, inOutDataBufferPtrPtr);
        } while (err == eDSBufferTooSmall);
    } while ( (err == eDSNoErr) && (*outDirNodeCount == 0) && (*inOutContinueData != 0) );
    
    return err;
}

static tDirStatus dsGetRecordListQ(
								   tDirNodeReference       inDirReference,
								   tDirNodeReference       inDirNodeReference,
								   tDataBufferPtr *        inOutDataBufferPtr,
								   tDataListPtr            inRecordNameList,
								   tDirPatternMatch        inPatternMatchType,
								   tDataListPtr            inRecordTypeList,
								   tDataListPtr            inAttributeTypeList,
								   dsBool                  inAttributeInfoOnly,
								   UInt32                  *inOutRecordEntryCount,
								   tContextData            *inOutContinueData
								   )
// A wrapper for dsGetRecordList that handles two special cases:
//
// o If the routine returns eDSBufferTooSmall, it doubles the 
//   size of the buffer referenced by *inOutDataBufferPtr 
//   and retries.
//
//   Note that this change requires a change of the function 
//   prototype; the second parameter is a pointer to a pointer 
//   to the buffer, rather than just a pointer to the buffer. 
//   This is so that I can modify the client's buffer pointer.
//
// o If the routine returns no records but there's valid continue data, 
//   it retries.
//
// In other respects this works just like dsGetRecordList.
{
    tDirStatus      err;
    UInt32          originalRecordCount;
    
    // I only supply pre-conditions for the parameters that I touch.
    assert( inOutDataBufferPtr != NULL);
    assert(*inOutDataBufferPtr != NULL);
    assert(inOutRecordEntryCount != NULL);
    assert(inOutContinueData != NULL);
    
    originalRecordCount = *inOutRecordEntryCount;
	
    do {
        *inOutRecordEntryCount = originalRecordCount;
        do {
            err = dsGetRecordList(
								  inDirNodeReference,
								  *inOutDataBufferPtr,
								  inRecordNameList,
								  inPatternMatchType,
								  inRecordTypeList,
								  inAttributeTypeList,
								  inAttributeInfoOnly,
								  inOutRecordEntryCount,
								  inOutContinueData
								  );
            DoubleTheBufferSizeIfItsTooSmall(&err, inDirReference, inOutDataBufferPtr);
        } while (err == eDSBufferTooSmall);
    } while ( (err == eDSNoErr) && (*inOutRecordEntryCount == 0) && (*inOutContinueData != 0) );
    
    return err;
}

static tDirStatus dsDoDirNodeAuthQ(
								   tDirNodeReference   inDirReference,
								   tDirNodeReference   inDirNodeReference,
								   tDataNodePtr        inDirNodeAuthName,
								   dsBool              inDirNodeAuthOnlyFlag,
								   tDataBufferPtr      inAuthStepData,
								   tDataBufferPtr *    outAuthStepDataResponsePtr,
								   tContextData        *inOutContinueData
								   )
// A wrapper for dsDoDirNodeAuth that handles a special cases, 
// to wit, if dsDoDirNodeAuth returns eDSBufferTooSmall, it doubles 
// the size of the buffer referenced by *outAuthStepDataResponsePtr 
// and retries.
//
// Note that this change requires a change of the function 
// prototype; the second parameter is a pointer to a pointer 
// to the buffer, rather than just a pointer to the buffer. 
// This is so that I can modify the client's buffer pointer.
//
// In other respects this works just like dsDoDirNodeAuth.
{
    tDirStatus  err;
    
    // I only supply pre-conditions for the parameters that I touch.
    assert( outAuthStepDataResponsePtr != NULL);
    assert(*outAuthStepDataResponsePtr != NULL);
    
    do {
        err = dsDoDirNodeAuth(
							  inDirNodeReference, 
							  inDirNodeAuthName, 
							  inDirNodeAuthOnlyFlag, 
							  inAuthStepData, 
							  *outAuthStepDataResponsePtr, 
							  inOutContinueData
							  );
        DoubleTheBufferSizeIfItsTooSmall(&err, inDirReference, outAuthStepDataResponsePtr);
    } while (err == eDSBufferTooSmall);
    
    return err;
}

// ***** Authentication Code

static tDirStatus GetSearchNodePathList(tDirReference dirRef, tDataListPtr * searchNodePathListPtr)
// Returns the path to the Open Directory search node.
// dirRef is the connection to Open Directory.
// On success, *searchNodePathListPtr is a data list that 
// contains the search node's path components.
{
    tDirStatus          err;
    tDirStatus          junk;
    tDataBufferPtr      buf;
    tDirPatternMatch    patternToFind;
    UInt32              nodeCount;
    tContextData        context;
    
    assert(dirRef != 0);
    assert( searchNodePathListPtr != NULL);
    assert(*searchNodePathListPtr == NULL);
	
    if (gOpenDirectoryAllowLocalUsersOnly) {
        patternToFind = eDSLocalNodeNames;
    } else {
        patternToFind = eDSAuthenticationSearchNodeName;
    }
    
    context = 0;
    
    // Allocate a buffer for the node find results.  We'll grow 
    // this buffer if it proves to be to small.
    
    buf = dsDataBufferAllocate(dirRef, kDefaultDSBufferSize);
    err = eDSNoErr;
    if (buf == NULL) {
        err = eDSAllocationFailed;
    }
    
    // Find the node.  Note that this is a degenerate case because 
    // we're only looking for a single node, the search node, so 
    // we don't need to loop calling dsFindDirNodes, which is the 
    // standard way of using dsFindDirNodes.
    
    if (err == eDSNoErr) {
        err = dsFindDirNodesQ(
							  dirRef, 
							  &buf,                               // place results here
							  NULL,                               // no pattern, rather...
							  patternToFind,                      // ... hardwired search type
							  &nodeCount, 
							  &context
							  );
    }
    
    // If we didn't find any nodes, that's bad.
    
    if ( (err == eDSNoErr) && (nodeCount < 1) ) {
        err = eDSNodeNotFound;
    }
    
    // Grab the first node from the buffer.  Note that the inDirNodeIndex 
    // parameter to dsGetDirNodeName is one-based, so we pass in the constant 
    // 1.
    // 
    // Also, if we found more than one, that's unusual, but not enough to 
    // cause us to error.
    
    if (err == eDSNoErr) {
        if (nodeCount > 1) {
            fprintf(stderr, "GetSearchNodePathList: nodeCount = %lu, weird.\n", (unsigned long) nodeCount);
        }
        err = dsGetDirNodeName(dirRef, buf, 1, searchNodePathListPtr);
    }
    
    // Clean up.
    
    if (context != 0) {
        junk = dsReleaseContinueData(dirRef, context);
        assert(junk == eDSNoErr);
    }
    if (buf != NULL) {
        junk = dsDataBufferDeAllocate(dirRef, buf);
        assert(junk == eDSNoErr);
    }
    
    assert( (err == eDSNoErr) == (*searchNodePathListPtr != NULL) );
    
    return err;
}

static tDirStatus FindUsersAuthInfo(
									tDirReference       dirRef, 
									tDirNodeReference   nodeRef, 
									const char *        username, 
									tDataListPtr *      pathListToAuthNodePtr,
									char * *            userNameForAuthPtr
									)
// Finds the authentication information for a given user. 
// dirRef is the connection to Open Directory.
// nodeRef is the node to use to do the searching.  Typically 
// this is the authentication search node, whose path is found 
// using GetSearchNodePathList.  username is the user whose 
// information we're looking for.
//
// On success, *pathListToAuthNodePtr is a data list that 
// contain's the path components of the authentication node 
// for the specified user.
// On success, *userNameForAuthPtr contains a pointer to C string 
// that is the user's name for authentication.  This can be 
// different from username.  For example, if user's long name is 
// "Mr Gumby" and their short name is "mrgumby", username can be 
// either the long name or the short name, but *userNameForAuthPtr 
// will always be the short name.  The caller is responsible for 
// freeing this string using free.
{
    tDirStatus          err;
    tDirStatus          junk;
    tDataBufferPtr      buf;
    tDataListPtr        recordType;
    tDataListPtr        recordName;
    tDataListPtr        requestedAttributes;
    UInt32              recordCount;
    tAttributeListRef   foundRecAttrList;
    tContextData        context;
    tRecordEntryPtr     foundRecEntry;
    tDataListPtr        pathListToAuthNode;
    char *              userNameForAuth;
	
    assert(dirRef != 0);
    assert(nodeRef != 0);
    assert(username != NULL);
    assert( pathListToAuthNodePtr != NULL);
    assert(*pathListToAuthNodePtr == NULL);
    assert( userNameForAuthPtr != NULL);
    assert(*userNameForAuthPtr == NULL);
	
    recordType = NULL;
    recordName = NULL;
    requestedAttributes = NULL;
    foundRecAttrList = 0;
    context = 0;
    foundRecEntry = NULL;
    pathListToAuthNode = NULL;
    userNameForAuth = NULL;
    
    // Allocate a buffer for the record results.  We'll grow this 
    // buffer if it proves to be too small.
    
    err = eDSNoErr;
    buf = dsDataBufferAllocate(dirRef, kDefaultDSBufferSize);
    if (buf == NULL) {
        err = eDSAllocationFailed;
    }
	
    // Create the information needed for the search.  We're searching for 
    // a record of type kDSStdRecordTypeUsers whose name is "username".  
    // We want to get back the kDSNAttrMetaNodeLocation and kDSNAttrRecordName 
    // attributes.
    
    if (err == eDSNoErr) {
        recordType = dsBuildListFromStrings(dirRef, kDSStdRecordTypeUsers, NULL);
        recordName = dsBuildListFromStrings(dirRef, username, NULL);
        requestedAttributes = dsBuildListFromStrings(dirRef, kDSNAttrMetaNodeLocation, kDSNAttrRecordName, NULL);
		
        if ( (recordType == NULL) || (recordName == NULL) || (requestedAttributes == NULL) ) {
            err = eDSAllocationFailed;
        }
    }
    
    // Search for a matching record.
    
    if (err == eDSNoErr) {
        recordCount = 1;            // we only want one match (the first)
        
        err = dsGetRecordListQ(
							   dirRef,
							   nodeRef,
							   &buf,
							   recordName,
							   eDSExact,
							   recordType,
							   requestedAttributes,
							   false,
							   &recordCount,
							   &context
							   );
    }
    if ( (err == eDSNoErr) && (recordCount < 1) ) {
        err = eDSRecordNotFound;
    }
    
    // Get the first record from the search.  Then enumerate the attributes for 
    // that record.  For each attribute, extract the first value (remember that 
    // attributes can by multi-value).  Then see if the attribute is one that 
    // we care about.  If it is, remember the value for later processing.
    
    if (err == eDSNoErr) {
        assert(recordCount == 1);       // we only asked for one record, shouldn't get more back
		
        err = dsGetRecordEntry(nodeRef, buf, 1, &foundRecAttrList, &foundRecEntry);
    }
    if (err == eDSNoErr) {
        UInt32  attrIndex;
        
        // Iterate over the attributes.
        
        for (attrIndex = 1; attrIndex <= foundRecEntry->fRecordAttributeCount; attrIndex++) {
            tAttributeValueListRef  thisValue;
            tAttributeEntryPtr      thisAttrEntry;
            tAttributeValueEntryPtr thisValueEntry;
            const char *            thisAttrName;
            
            thisValue = 0;
            thisAttrEntry = NULL;
            thisValueEntry = NULL;
            
            // Get the information for this attribute.
            
            err = dsGetAttributeEntry(nodeRef, buf, foundRecAttrList, attrIndex, &thisValue, &thisAttrEntry);
			
            if (err == eDSNoErr) {
                thisAttrName = thisAttrEntry->fAttributeSignature.fBufferData;
				
                // We only care about attributes that have values.
                
                if (thisAttrEntry->fAttributeValueCount > 0) {
					
                    // Get the first value for this attribute.  This is common code for 
                    // the two potential attribute values listed below, so we do it first.
					
                    err = dsGetAttributeValue(nodeRef, buf, 1, thisValue, &thisValueEntry);
                    
                    if (err == eDSNoErr) {
                        const char *    thisValueDataPtr;
                        unsigned long   thisValueDataLen;
						
                        thisValueDataPtr = thisValueEntry->fAttributeValueData.fBufferData;
                        thisValueDataLen = thisValueEntry->fAttributeValueData.fBufferLength;
						
                        // Handle each of the two attributes we care about; ignore any others.
                        
                        if ( strcmp(thisAttrName, kDSNAttrMetaNodeLocation) == 0 ) {
                            assert(pathListToAuthNode == NULL);        // same attribute twice
                            
                            // This is the kDSNAttrMetaNodeLocation attribute, which contains 
                            // a path to the node used for authenticating this record; convert 
                            // its value into a path list.
                            
                            pathListToAuthNode = dsBuildFromPath(
																 dirRef, 
																 thisValueDataPtr, 
																 "/"
																 );
                            if (pathListToAuthNode == NULL) {
                                err = eDSAllocationFailed;
                            }
                        } else if ( strcmp(thisAttrName, kDSNAttrRecordName) == 0 ) {
                            assert(userNameForAuth == NULL);            // same attribute twice
                            
                            // This is the kDSNAttrRecordName attribute, which contains the 
                            // user name used for authentication; remember its value in a
                            // freshly allocated string.
							
                            userNameForAuth = (char *) malloc( thisValueDataLen + 1 );
                            if (userNameForAuth == NULL) {
                                err = eDSAllocationFailed;
                            } else {
                                memcpy(
									   userNameForAuth, 
									   thisValueDataPtr, 
									   thisValueDataLen
									   );
                                userNameForAuth[thisValueDataLen] = 0;  // terminating null
                            }
                        } else {
                            fprintf(stderr, "FindUsersAuthInfo: Unexpected attribute '%s'.", thisAttrName);
                        }
                    }
                } else {
                    fprintf(stderr, "FindUsersAuthInfo: Unexpected no-value attribute '%s'.", thisAttrName);
                }
            }
			
            // Clean up.
            
            if (thisValueEntry != NULL) {
                junk = dsDeallocAttributeValueEntry(dirRef, thisValueEntry);
                assert(junk == eDSNoErr);
            }
            if (thisValue != 0) {
                junk = dsCloseAttributeValueList(thisValue);
                assert(junk == eDSNoErr);
            }
            if (thisAttrEntry != NULL) {
                junk = dsDeallocAttributeEntry(dirRef, thisAttrEntry);
                assert(junk == eDSNoErr);
            }
            
            if (err != eDSNoErr) {
                break;
            }
        }
    }
    
    // Copy results out to caller.
    
    if (err == eDSNoErr) {
        if ( (pathListToAuthNode != NULL) && (userNameForAuth != NULL) ) {
            // Copy out results.
            
            *pathListToAuthNodePtr = pathListToAuthNode;
            *userNameForAuthPtr = userNameForAuth;
            
            // NULL out locals so that we don't dispose them.
            
            pathListToAuthNode = NULL;
            userNameForAuth = NULL;
        } else {
            err = eDSAttributeNotFound;
        }
    }
	
    // Clean up.
	
    if (pathListToAuthNode != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, pathListToAuthNode);
        assert(junk == eDSNoErr);
    }
    if (userNameForAuth != NULL) {
        free(userNameForAuth);
    }
    if (foundRecAttrList != 0) {
        junk = dsCloseAttributeList(foundRecAttrList);
        assert(junk == eDSNoErr);
    }
    if (context != 0) {
        junk = dsReleaseContinueData(dirRef, context);
        assert(junk == eDSNoErr);
    }
    if (foundRecAttrList != 0) {
        junk = dsDeallocRecordEntry(dirRef, foundRecEntry);
        assert(junk == eDSNoErr);
    }
    if (requestedAttributes != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, requestedAttributes);
        assert(junk == eDSNoErr);
    }
    if (recordName != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, recordName);
        assert(junk == eDSNoErr);
    }
    if (recordType != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, recordType);
        assert(junk == eDSNoErr);
    }
    if (buf != NULL) {
        junk = dsDataBufferDeAllocate(dirRef, buf);
        assert(junk == eDSNoErr);
    }
	
    assert( (err == eDSNoErr) == ( (*pathListToAuthNodePtr != NULL) && (*userNameForAuthPtr != NULL) ) );
	
    return err;
}

static tDirStatus AuthenticateWithNode(
									   tDirReference       dirRef, 
									   tDataListPtr        pathListToAuthNode,
									   const char *        userNameForAuth, 
									   const char *        password
									   )
// Authenticate a user with their authentication node.
// dirRef is the connection to Open Directory.
// pathListToAuthNode is a data list that contain's the 
// path components of the authentication node for the 
// specified user.  userNameForAuth and password are the 
// user name and password to authenticate.
{
    tDirStatus          err;
    tDirStatus          junk;
    size_t              userNameLen;
    size_t              passwordLen;
    size_t              bufferSize;
    UInt32              bufferSize32;
    tDirNodeReference   authNodeRef;
    tDataNodePtr        authMethod;
    tDataBufferPtr      authOutBuf;
    tDataBufferPtr      authInBuf;
    UInt32              length;
    
    assert(dirRef != 0);
    assert(pathListToAuthNode != NULL);
    assert(userNameForAuth != NULL);
    assert(password != NULL);
    
    authNodeRef = 0;
    authMethod = NULL;
    authOutBuf = NULL;
    authInBuf = NULL;
	
    userNameLen = strlen(userNameForAuth);
    passwordLen = strlen(password);
	
    // Open the authentication node.
    
    err = dsOpenDirNode(dirRef, pathListToAuthNode, &authNodeRef);
    
    // Create the input parameters to dsDoDirNodeAuth and then call it.  The most 
    // complex input parameter to dsDoDirNodeAuth is authentication data itself, 
    // held in authInBuf.  This holds the following items:
    //
    // 4 byte length of user name
    // user name
    // 4 byte length of password
    // password
    
    if (err == eDSNoErr) {
        authMethod = dsDataNodeAllocateString(dirRef, kDSStdAuthNodeNativeClearTextOK);
        if (authMethod == NULL) {
            err = eDSAllocationFailed;
        }
    }
	
    // Allocate some arbitrary amount of space for the authOutBuf.  This 
    // buffer comes back containing a credential generated by the 
    // authentication (apparently a kDS1AttrAuthCredential).  However, 
    // we never need this information, so we basically just create the 
    // buffer, pass it in to dsDoDirNodeAuth, and then throw it away. 
    // Unfortunately dsDoDirNodeAuth won't let us pass in NULL.
    
    if (err == eDSNoErr) {
        authOutBuf = dsDataBufferAllocate(dirRef, kDefaultDSBufferSize);
        if (authOutBuf == NULL) {
            err = eDSAllocationFailed;
        }
    }
    
    // Calculate the size of the buffer authentication data buffer.  This is 
    // complicated by the fact that userNameLen and passwordLen are size_t, which 
    // may or may not be 64-bit.  Also, even if they are 32-bit, the sum might 
    // overflow the UInt32 size parameter to dsDataBufferAllocate.  The following 
    // relies on the fact that, if you add two unsigned numbers and the sum 
    // is less than one of the inputs (either one in fact), you've overflowed.
    
    if (err == eDSNoErr) {
        bufferSize = sizeof(UInt32) + sizeof(UInt32);
        bufferSize += userNameLen;
        if (bufferSize < userNameLen) {
            err = eDSBufferTooSmall;
        }
    }
    if (err == eDSNoErr) {
        bufferSize += passwordLen;
        if (bufferSize < passwordLen) {
            err = eDSBufferTooSmall;
        }
    }
    if (err == eDSNoErr) {
        bufferSize32 = (UInt32) bufferSize;
        if ( ((size_t) bufferSize32) != bufferSize ) {
            err = eDSBufferTooSmall;
        }
    }
    
    // Allocate and populate the authentication data buffer.  We know that the 
    // (potential) truncations of userNameLen and passwordLen will not cause problems 
    // because, if they are 64-bits (meaning that truncation might be an issue) 
    // and bigger than what will fit in a UInt32 (meaning that truncation will change 
    // the value), we'll detect that when calculating the buffer size.
    
    if (err == eDSNoErr) {
        authInBuf = dsDataBufferAllocate(dirRef, bufferSize32);
        if (authInBuf == NULL) {
            err = eDSAllocationFailed;
        }
    }
    if (err == eDSNoErr) {
        length = (UInt32) userNameLen;
        junk = dsDataBufferAppendData(authInBuf, &length, sizeof(length));
        assert(junk == noErr);
		
        junk = dsDataBufferAppendData(authInBuf, userNameForAuth, userNameLen);
        assert(junk == noErr);
		
        length = (UInt32) passwordLen;
        junk = dsDataBufferAppendData(authInBuf, &length, sizeof(length));
        assert(junk == noErr);
		
        junk = dsDataBufferAppendData(authInBuf, password, passwordLen);
        assert(junk == noErr);
		
        // Call dsDoDirNodeAuth to do the authentication.
        
        err = dsDoDirNodeAuthQ(dirRef, authNodeRef, authMethod, true, authInBuf, &authOutBuf, NULL);
    }
	
    // Clean up.
	
    if (authInBuf != NULL) {
        junk = dsDataBufferDeAllocate(dirRef, authInBuf);
        assert(junk == eDSNoErr);
    }
    if (authOutBuf != NULL) {
        junk = dsDataBufferDeAllocate(dirRef, authOutBuf);
        assert(junk == eDSNoErr);
    }
    if (authMethod != NULL) {
        junk = dsDataNodeDeAllocate(dirRef, authMethod);
        assert(junk == eDSNoErr);
    }
    if (authNodeRef != 0) {
        junk = dsCloseDirNode(authNodeRef);
        assert(junk == eDSNoErr);
    }
    
    return err;
}

static tDirStatus CheckPasswordUsingOpenDirectory(const char *username, const char *password)
// Check a user name and password using Open Directory.
{
    tDirStatus              err;
    tDirStatus              junk;
    tDirReference           dirRef;
    tDataListPtr            pathListToSearchNode;
    tDirNodeReference       searchNodeRef;
    tDataListPtr            pathListToAuthNode;
    char *                  userNameForAuth;
	
    assert(username != NULL);
    assert(password != NULL);
    
    dirRef = 0;
    pathListToSearchNode = NULL;
    searchNodeRef = 0;
    pathListToAuthNode = NULL;
    userNameForAuth = NULL;
    
    // Connect to Open Directory.
    
    err = dsOpenDirService(&dirRef);
	
    // Open the search node.
	
    if (err == eDSNoErr) {
        err = GetSearchNodePathList(dirRef, &pathListToSearchNode);
    }
    if (err == eDSNoErr) {
        err = dsOpenDirNode(dirRef, pathListToSearchNode, &searchNodeRef);
    }
    
    // Search for the user's record and extract the user's authentication 
    // node and authentication user name..
    
    if (err == eDSNoErr) {
        err = FindUsersAuthInfo(dirRef, searchNodeRef, username, &pathListToAuthNode, &userNameForAuth);
    }
    
    // Open the authentication node and do the authentication.
    
    if (err == eDSNoErr) {
        err = AuthenticateWithNode(dirRef, pathListToAuthNode, userNameForAuth, password);
    }
    
    // Clean up.
	
    if (userNameForAuth != NULL) {
        free(userNameForAuth);
    }
    if (pathListToAuthNode != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, pathListToAuthNode);
        assert(junk == eDSNoErr);
    }
    if (searchNodeRef != 0) {
        junk = dsCloseDirNode(searchNodeRef);
        assert(junk == eDSNoErr);
    }
    if (pathListToSearchNode != NULL) {
        junk = dsDataListAndHeaderDeallocate(dirRef, pathListToSearchNode);
        assert(junk == eDSNoErr);
    }
    if (dirRef != 0) {
        junk = dsCloseDirService(dirRef);
        assert(junk == eDSNoErr);
    }
    
    return err;
}

static PyObject *
authenticate(PyObject *self, PyObject *args)
{
    const char *username;
	const char *password;
	
    if (!PyArg_ParseTuple(args, "ss", &username, &password))
        return NULL;
	
    tDirStatus              err;
	
	err = CheckPasswordUsingOpenDirectory(username, password);
	if (err == 0) {
		return Py_True;
	} else {
		return Py_False;
	}

	/*
	 Base for some error management:
	 switch (err) {
		case eDSNoErr:
			fprintf(stdout, "Authenticated!\n");
			break;
		case eDSAuthFailed:
			fprintf(stdout, "Authentication failed.\n");
			break;
		case eDSRecordNotFound:
			fprintf(stdout, "Authentication failed because directory record was not found.\n");
			break;
		case eDSAuthNewPasswordRequired:
			fprintf(stdout, "Authentication failed because a new password is required.\n");
			fprintf(stdout, "Your password is correct but we won't let you log in \n");
			fprintf(stdout, "because this code isn't smart enough to allow you to change \n");
			fprintf(stdout, "your password.\n");
			break;
		case eDSAuthPasswordExpired:
			fprintf(stdout, "Authentication failed because the password has expired.\n");
			fprintf(stdout, "Your password is correct but we won't let you log in \n");
			fprintf(stdout, "because this code isn't smart enough to handle this case.\n");
			break;
		case eDSAuthAccountInactive:
			fprintf(stdout, "Authentication failed because the account is inactive.\n");
			break;
		case eDSAuthAccountExpired:
			fprintf(stdout, "Authentication failed because the account has expired.\n");
			break;
		case eDSAuthAccountDisabled:
			fprintf(stdout, "Authentication failed because the account is disabled.\n");
			break;
		default:
			fprintf(stdout, "Authentication failed because of an unexpected error (%d).\n", (int) err);
			break;
	} */
}

PyMODINIT_FUNC initOpenDirectoryAuth()
{
    (void) Py_InitModule("OpenDirectoryAuth", methods);
}
