/*
  JDokan : Java library for Dokan

  Copyright (C) 2008 Yu Kobayashi http://yukoba.accelart.jp/

  http://decas-dev.net/en

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winbase.h>
#include <accctrl.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "../dokan/dokan.h"
#include "../dokan/fileinfo.h"
#include "stdafx.h"
#include "net_decasdev_dokan_Dokan.h"
#include "JDokanDLL.h"
#include "Utils.h"
#include "DokanObjUtils.h"
#include "IDs.h"


/*
 * Class:     net_decasdev_dokan_Dokan
 * Method:    mount
 * Signature: (Lnet/decasdev/dokan/DokanOptions;Lnet/decasdev/dokan/DokanOperations;)I
 */

NTSTATUS ToNtStatus(DWORD dwError)
{
	switch (dwError)
	{
	case ERROR_SUCCESS:
		return STATUS_SUCCESS;
	case ERROR_MAX_THRDS_REACHED:
		return STATUS_TOO_MANY_THREADS;
	case ERROR_DISK_FULL:
		return STATUS_DISK_FULL;
	case ERROR_READ_FAULT:
		return STATUS_UNEXPECTED_IO_ERROR;
	case ERROR_WRITE_FAULT:
		return STATUS_UNEXPECTED_IO_ERROR;
	case ERROR_FILE_NOT_FOUND:
		return STATUS_OBJECT_NAME_NOT_FOUND;
	case ERROR_PATH_NOT_FOUND:
		return STATUS_OBJECT_PATH_NOT_FOUND;
	case ERROR_INVALID_PARAMETER:
		return STATUS_INVALID_PARAMETER;
	case ERROR_DIR_NOT_EMPTY:
		return STATUS_DIRECTORY_NOT_EMPTY;
	case ERROR_ACCESS_DENIED:
		return STATUS_ACCESS_DENIED;
	case ERROR_SHARING_VIOLATION:
		return STATUS_SHARING_VIOLATION;
	case ERROR_INVALID_NAME:
		return STATUS_OBJECT_NAME_NOT_FOUND;
	case ERROR_FILE_EXISTS:
	case ERROR_ALREADY_EXISTS:
		return STATUS_OBJECT_NAME_COLLISION;
	case ERROR_PRIVILEGE_NOT_HELD:
		return STATUS_PRIVILEGE_NOT_HELD;
	case ERROR_NOT_READY:
		return STATUS_DEVICE_NOT_READY;
	default:
		return STATUS_ACCESS_DENIED;
	}
}

BOOL g_UseStdErr;
BOOL g_DebugMode;

static void DbgPrint(LPCWSTR format, ...) {
	if (g_DebugMode) {
		const WCHAR *outputString;
		WCHAR *buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = (WCHAR *)_malloca(length * sizeof(WCHAR));
		if (buffer) {
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		}
		else {
			outputString = format;
		}
		if (g_UseStdErr)
			fputws(outputString, stderr);
		else
			OutputDebugStringW(outputString);
		if (buffer)
			_freea(buffer);
		va_end(argp);
	}
}

static void
PrintUserName(PDOKAN_FILE_INFO	DokanFileInfo)
{
	HANDLE	handle;
	UCHAR buffer[1024];
	DWORD returnLength;
	WCHAR accountName[256];
	WCHAR domainName[256];
	DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
	DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
	PTOKEN_USER tokenUser;
	SID_NAME_USE snu;

	handle = DokanOpenRequestorToken(DokanFileInfo);
	if (handle == INVALID_HANDLE_VALUE) {
		return;
	}

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer), &returnLength)) {
		CloseHandle(handle);
		return;
	}

	CloseHandle(handle);

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName,
		&accountLength, domainName, &domainLength, &snu)) {
		return;
	}
}

int SetPrivilege(LPCWSTR privilege, int enable)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE token;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) return 0;
	if (!LookupPrivilegeValue(NULL, privilege, &luid)) return 0;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (enable) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else tp.Privileges[0].Attributes = 0;
	int rstl = AdjustTokenPrivileges(token, 0, &tp, NULL, NULL, NULL);
	CloseHandle(token);
	return rstl;
}

static BOOL AddSeSecurityNamePrivilege() {
	if (!SetPrivilege(SE_SECURITY_NAME,1)) {
		int err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
			return FALSE;
		}
	}
	if (!SetPrivilege(SE_TAKE_OWNERSHIP_NAME, 1)) {
		int err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
			return FALSE;
		}
	}
	if (!SetPrivilege(SE_BACKUP_NAME, 1)) {
		int err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
			return FALSE;
		}
	}
	if (!SetPrivilege(SE_RESTORE_NAME, 1)) {
		int err = GetLastError();
		if (err != ERROR_SUCCESS) {
			DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
			return FALSE;
		}
	}
	return TRUE;
}






JNIEXPORT jint JNICALL Java_net_decasdev_dokan_Dokan_mount
(JNIEnv *env, jclass, jobject joptions, jobject joperations,jboolean debug)
{
	try {
		if (jvm != NULL)
			throw "You cannot mount twice at this version of Dokan";
		env->GetJavaVM(&jvm);
		gOperations = env->NewGlobalRef(joperations);

		InitMethodIDs(env);
		g_UseStdErr = true;
		g_DebugMode = debug;
		DOKAN_OPTIONS options;
		ZeroMemory(&options, sizeof(DOKAN_OPTIONS));
		options.Version = DOKAN_VERSION;
		/* mountPoint */
		jstring mountPoint = (jstring)env->GetObjectField(joptions, mountPointID);
		jstring metaFilePath = (jstring)env->GetObjectField(joptions, metaFilePathID);
		jstring unc = (jstring)env->GetObjectField(joptions, uncPathID);
		if (unc != NULL) {
			int ulen = env->GetStringLength(unc);
			const jchar* uchars = env->GetStringChars(unc, NULL);
			wchar_t* uwsz = new wchar_t[ulen + 1];
			memcpy(uwsz, uchars, ulen * 2);
			options.UNCName = uwsz;
			uwsz[ulen] = 0;
			options.UNCName = uwsz;
			env->ReleaseStringChars(unc, uchars);
		}
		int len = env->GetStringLength(mountPoint);
		const jchar* chars = env->GetStringChars(mountPoint, NULL);
		wchar_t* wsz = new wchar_t[len + 1];
		memcpy(wsz, chars, len * 2);
		wsz[len] = 0;
		options.MountPoint = wsz;
		env->ReleaseStringChars(mountPoint, chars);
		/* end MountPoint */
		options.ThreadCount = env->GetIntField(joptions, threadCountID);
		options.Options = env->GetLongField(joptions, optionsModeID);
		DOKAN_OPERATIONS operations;
		ZeroMemory(&operations, sizeof(DOKAN_OPERATIONS));
		operations.ZwCreateFile = OnCreateFile;
		operations.Cleanup = OnCleanup;
		operations.CloseFile = OnCloseFile;
		operations.ReadFile = OnReadFile;
		operations.WriteFile = OnWriteFile;
		operations.FlushFileBuffers = OnFlushFileBuffers;
		operations.GetFileInformation = OnGetFileInformation;
		operations.FindFiles = OnFindFiles;
		operations.FindFilesWithPattern = NULL;
		operations.SetFileAttributesW = OnSetFileAttributes;
		operations.SetFileTime = OnSetFileTime;
		operations.DeleteFileW = OnDeleteFile;
		operations.DeleteDirectory = OnDeleteDirectory;
		operations.MoveFileW = OnMoveFile;
		operations.SetEndOfFile = OnSetEndOfFile;
		operations.LockFile = OnLockFile;
		operations.UnlockFile = OnUnlockFile;
		operations.GetDiskFreeSpace = OnGetDiskFreeSpace;
		operations.GetVolumeInformation = OnGetVolumeInformation;
		if (metaFilePath != NULL) {
			int mlen = env->GetStringLength(metaFilePath);
			const jchar* str = env->GetStringChars(metaFilePath, NULL);
			wchar_t* swsz = new wchar_t[mlen + 1];
			memcpy(swsz, str, mlen * 2);
			swsz[mlen] = 0;
			wcscpy_s(RootDirectory, sizeof(RootDirectory) / sizeof(WCHAR), swsz);
			operations.GetFileSecurityW = onGetFileSecurity;
			operations.SetFileSecurityW = onSetFileSecurity;
			DbgPrint(L"GetFileSecurity %s\n", RootDirectory);
			if (!AddSeSecurityNamePrivilege()) {
				printf("  Failed to add security privilege to process\n");
				free(&operations);
				free(&options);
				return -1;
			}
			
		}
		operations.Unmounted = OnUnmount;
		int st = DokanMain(&options, &operations);
		free(&operations);
		free(&options);
		return st;
	}
	catch (const char* msg) {
		env->ThrowNew(env->FindClass("java/lang/NoSuchFieldError"), msg);
		return FALSE;
	}
}

static void
GetFilePath(
PWCHAR	filePath,
ULONG	numberOfElements,
LPCWSTR FileName)
{
	filePath[0] = 0;
	wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));
	wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
	RtlZeroMemory(filePath + wcslen(filePath), (numberOfElements - wcslen(filePath)) * sizeof(WCHAR));
}

NTSTATUS DOKAN_CALLBACK OnCreateFile(
	LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo)

{


	DbgPrint(L"[OnCreateFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		jlong handle = env->CallLongMethod(gOperations, onCreateFileID, 
			jfileName, DesiredAccess, ShareAccess, CreateDisposition,FileAttributes,
			CreateOptions, jdokanFileInfo);
		result = GetOperationResult(env);

		if (result == 0) {
			DokanFileInfo->Context = handle;
		}
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		DbgPrint(L"[OnCreateFile] result = %d, handle = %d\n", result, handle);
	} catch(const char* msg) {
		DbgPrint(L"[OnCreateFile] %s\n", msg);
	}

	release_env(env);
	return ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK
onGetFileSecurity(
	LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
	PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
	DbgPrint(L"0GetFileSecurity");
	WCHAR	filePath[MAX_PATH];


	UNREFERENCED_PARAMETER(DokanFileInfo);
	DbgPrint(L"1GetFileSecurity %s\n", filePath);
	GetFilePath(filePath, MAX_PATH, FileName);

	DbgPrint(L"2GetFileSecurity %s\n", filePath);
	HANDLE handle = CreateFile(
		filePath,
		READ_CONTROL | (((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
			(*SecurityInformation & BACKUP_SECURITY_INFORMATION))
			? ACCESS_SYSTEM_SECURITY
			: 0),
		FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
		NULL, // security attribute
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
		NULL);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle\n\n");
		int error = GetLastError();
		return ToNtStatus(error);
	}


	if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
		BufferLength, LengthNeeded)) {
		int error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER) {
			DbgPrint(L"  GetUserObjectSecurity failed: ERROR_INSUFFICIENT_BUFFER %s\n",filePath);
			CloseHandle(handle);
			return ToNtStatus(error);
		}
		else {
			DbgPrint(L"  GetUserObjectSecurity failed: %d\n", error);
			CloseHandle(handle);
			return ToNtStatus(error);
		}
	}
	CloseHandle(handle);

	return STATUS_SUCCESS;
	
}


NTSTATUS DOKAN_CALLBACK
onSetFileSecurity(
LPCWSTR					FileName,
PSECURITY_INFORMATION	SecurityInformation,
PSECURITY_DESCRIPTOR	SecurityDescriptor,
ULONG				SecurityDescriptorLength,
PDOKAN_FILE_INFO	DokanFileInfo)
{
	WCHAR	filePath[MAX_PATH];
	DbgPrint(L"SetFileSecurity\n");
	UNREFERENCED_PARAMETER(SecurityDescriptorLength);

	GetFilePath(filePath, MAX_PATH, FileName);
	DbgPrint(L"SetFileSecurity %s\n", filePath);
	if (!SetFileSecurity(filePath, (SECURITY_INFORMATION)SecurityInformation, SecurityDescriptor)) {
		int error = GetLastError();
		DbgPrint(L"  SetUserObjectSecurity failed: %d\n", error);
		return ToNtStatus(error);
	}
	return STATUS_SUCCESS;
}

void DOKAN_CALLBACK OnCleanup(
	LPCWSTR      FileName,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnCleanup] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onCleanupID, 
			jfileName, jdokanFileInfo);
		GetOperationResult(env);
		if (DokanFileInfo->Context) {
			DokanFileInfo->Context = 0;
		}
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnCleanup] %s\n", msg);
	}

	release_env(env);
}

void DOKAN_CALLBACK OnCloseFile(
	LPCWSTR      FileName,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnCloseFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onCloseFileID, 
			jfileName, jdokanFileInfo);
		GetOperationResult(env);
		if (DokanFileInfo->Context) {
			DokanFileInfo->Context = 0;
		}
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnCloseFile] %s\n", msg);
	}

	release_env(env);
}

NTSTATUS DOKAN_CALLBACK OnReadFile(
	LPCWSTR  FileName,
	LPVOID   Buffer,
	DWORD    NumberOfBytesToRead,
	LPDWORD  NumberOfBytesRead,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnReadFile] FileName = %s, Offset = %lld, NumberOfBytesToRead = %d\n",
		FileName, Offset, NumberOfBytesToRead);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		jobject jRb = env->NewDirectByteBuffer(Buffer, NumberOfBytesToRead);
		DWORD readed = env->CallIntMethod(gOperations, onReadFileID, 
			jfileName, 
			jRb,
			Offset,
			jdokanFileInfo);
		if (NumberOfBytesRead)
			*NumberOfBytesRead = readed;
		result = GetOperationResult(env);
		DbgPrint(L"[OnReadFile] FileName = %s read=%d, offset=%d\n", FileName, *NumberOfBytesRead, Offset);
		if(result != 0) {
			DbgPrint(L"[OnReadFile] result = %d\n", result);
		}
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jRb != NULL) env->DeleteLocalRef(jRb);
	} catch(const char* msg) {
		DbgPrint(L"[OnReadFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnWriteFile(
	LPCWSTR  FileName,
	LPCVOID  Buffer,
	DWORD    NumberOfBytesToWrite,
	LPDWORD  NumberOfBytesWritten,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnWriteFile] FileName = %s, Offset = %lld, NumberOfBytesToWrite = %d\n",
		FileName, Offset, NumberOfBytesToWrite);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		jobject jWb = env->NewDirectByteBuffer((LPVOID)Buffer, NumberOfBytesToWrite);
		// Some one please modify here for the faster way !!
		/*
		LPVOID tmpBuffer = malloc(NumberOfBytesToWrite);
		if(tmpBuffer == NULL)
			throw "Cannot allocate memory";
		CopyMemory(tmpBuffer, Buffer, NumberOfBytesToWrite);
		*/
		DWORD written = env->CallIntMethod(gOperations, onWriteFileID, 
			jfileName, 
			jWb,
			Offset,
			jdokanFileInfo);

		if (NumberOfBytesWritten)
			*NumberOfBytesWritten = written;
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jWb != NULL) env->DeleteLocalRef(jWb);
		if(result != 0) {
			DbgPrint(L"[OnWriteFile] ERROR result = %d\n", result);
		} else {
			DbgPrint(L"[OnWriteFile] written = %d\n", written);
		}
	} catch(const char* msg) {
		DbgPrint(L"[OnWriteFile] %s\n", msg);
	}

	release_env(env);
	return STATUS_SUCCESS;;
}

NTSTATUS DOKAN_CALLBACK OnFlushFileBuffers(
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnFlushFileBuffers] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onFlushFileBuffersID, 
			jfileName, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		
	} catch(const char* msg) {
		DbgPrint(L"[OnFlushFileBuffers] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnGetFileInformation(
	LPCWSTR          FileName,
	LPBY_HANDLE_FILE_INFORMATION ByHandleFileInfo,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnGetFileInformation] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		jobject jobj = env->CallObjectMethod(gOperations, onGetFileInformationID, 
			jfileName, jdokanFileInfo);
		result = GetOperationResult(env);

		if (result == 0) {
			ToByHandleFileInfo(env, jobj, ByHandleFileInfo);
			DbgPrint(L"[OnGetFileInformation] info= %d %d %d\n",
				ByHandleFileInfo->dwFileAttributes,
				ByHandleFileInfo->nFileSizeHigh,
				ByHandleFileInfo->nFileSizeLow);
		}
		else {
			DbgPrint(L"[OnGetFileInformation] result=%d\n", result);
		}
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jobj != NULL) env->DeleteLocalRef(jobj);
	} catch(const char* msg) {
		DbgPrint(L"[OnGetFileInformation] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnFindFiles(
	LPCWSTR			PathName,
	PFillFindData	pFillFindData,		// call this function with PWIN32_FIND_DATAW
	PDOKAN_FILE_INFO DokanFileInfo)   // (see PFillFindData definition)
{
	DbgPrint(L"[OnFindFiles] PathName = %s\n", PathName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jpathName = ToJavaString(env, PathName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		jobjectArray ary = (jobjectArray)env->CallObjectMethod(gOperations, 
			onFindFilesID, 
			jpathName, jdokanFileInfo);
		result = GetOperationResult(env);

		if (result == 0 && ary != NULL && pFillFindData != NULL) {
			for(int i = 0; i < env->GetArrayLength(ary); i++) {
				WIN32_FIND_DATAW win32FindData;
				jobject obj = env->GetObjectArrayElement(ary, i);
				ToWin32FindData(env, obj, &win32FindData);
				pFillFindData(&win32FindData, DokanFileInfo);
				env->DeleteLocalRef(obj);
			}

		}
		if (jpathName != NULL) env->DeleteLocalRef(jpathName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		env->DeleteLocalRef(ary);
	} catch(const char* msg) {
		DbgPrint(L"[OnFindFiles] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

//You should implement either FindFires or FindFilesWithPattern
NTSTATUS DOKAN_CALLBACK OnFindFilesWithPattern(
	LPCWSTR			PathName,
	LPCWSTR			SearchPattern,
	PFillFindData	pFillFindData,		// call this function with PWIN32_FIND_DATAW
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnFindFilesWithPattern] PathName = %s\n", PathName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jpathName = ToJavaString(env, PathName);
		jstring jsearchPattern = ToJavaString(env, SearchPattern);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		jobjectArray ary = (jobjectArray)env->CallObjectMethod(gOperations, 
			onFindFilesWithPatternID, 
			jpathName, jsearchPattern, jdokanFileInfo);
		result = GetOperationResult(env);

		if (result == 0 && ary != NULL && pFillFindData != NULL) {
			for(int i = 0; i < env->GetArrayLength(ary); i++) {
				WIN32_FIND_DATAW win32FindData;
				jobject obj = env->GetObjectArrayElement(ary, i);
				ToWin32FindData(env, obj, &win32FindData);
				pFillFindData(&win32FindData, DokanFileInfo);

				env->DeleteLocalRef(obj);
			}
		}
		if(jpathName != NULL) env->DeleteLocalRef(jpathName);
		if (jsearchPattern != NULL) env->DeleteLocalRef(jsearchPattern);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		env->DeleteLocalRef(ary);
	} catch(const char* msg) {
		DbgPrint(L"[OnFindFilesWithPattern] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnSetFileAttributes(
	LPCWSTR FileName,
	DWORD   FileAttributes,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnSetFileAttributes] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onSetFileAttributesID, 
			jfileName, FileAttributes, jdokanFileInfo);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		result = GetOperationResult(env);
	} catch(const char* msg) {
		DbgPrint(L"[OnSetFileAttributes] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnSetFileTime(
	LPCWSTR		FileName,
	CONST FILETIME* CreationTime,
	CONST FILETIME* LastAccessTime,
	CONST FILETIME* LastWriteTime,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnSetFileTime] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onSetFileTimeID, 
			jfileName, FileTime2LongLong(CreationTime), 
			FileTime2LongLong(LastAccessTime), FileTime2LongLong(LastWriteTime), 
			jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnSetFileTime] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnDeleteFile(
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnDeleteFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onDeleteFileID, 
			jfileName, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnDeleteFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnDeleteDirectory(
	LPCWSTR FileName,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnDeleteDirectory] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onDeleteDirectoryID, 
			jfileName, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnDeleteDirectory] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnMoveFile(
	LPCWSTR ExistingFileName,
	LPCWSTR NewFileName,
	BOOL	ReplaceExisiting,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnMoveFile] ExistingFileName = %s\n", ExistingFileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jExistingFileName = ToJavaString(env, ExistingFileName);
		jstring jNewFileName = ToJavaString(env, NewFileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onMoveFileID, 
			jExistingFileName, jNewFileName, ReplaceExisiting, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jExistingFileName != NULL) env->DeleteLocalRef(jExistingFileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jNewFileName != NULL) env->DeleteLocalRef(jNewFileName);
	} catch(const char* msg) {
		DbgPrint(L"[OnMoveFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnSetEndOfFile(
	LPCWSTR  FileName,
	LONGLONG Length,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnSetEndOfFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onSetEndOfFileID, 
			jfileName, Length, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnSetEndOfFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnLockFile(
	LPCWSTR		FileName,
	LONGLONG	ByteOffset,
	LONGLONG	Length,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnLockFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onLockFileID, 
			jfileName, ByteOffset, Length, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnLockFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

NTSTATUS DOKAN_CALLBACK OnUnlockFile(
	LPCWSTR		FileName,
	LONGLONG	ByteOffset,
	LONGLONG	Length,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnUnlockFile] FileName = %s\n", FileName);
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jfileName = ToJavaString(env, FileName);
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onUnlockFileID, 
			jfileName, ByteOffset, Length, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jfileName != NULL) env->DeleteLocalRef(jfileName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnUnlockFile] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

// Neither GetDiskFreeSpace nor GetVolumeInformation
// save the DokanFileContext->Context.
// Before these methods are called, CreateFile may not be called.
// (ditto CloseFile and Cleanup)

// see Win32 API GetDiskFreeSpaceEx
NTSTATUS DOKAN_CALLBACK OnGetDiskFreeSpace(
	PULONGLONG FreeBytesAvailable,
	PULONGLONG TotalNumberOfBytes,
	PULONGLONG TotalNumberOfFreeBytes,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnGetDiskFreeSpace]\n");
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		NewDokanDiskFreeSpace(env);
		
		jobject jdiskFreeSpace = env->CallObjectMethod(gOperations, onGetDiskFreeSpaceID, jdokanFileInfo);
		result = GetOperationResult(env);

		if (FreeBytesAvailable)
			*FreeBytesAvailable = env->GetLongField(jdiskFreeSpace, freeBytesAvailableID);
		if (TotalNumberOfBytes)
			*TotalNumberOfBytes = env->GetLongField(jdiskFreeSpace, totalNumberOfBytesID);
		if (TotalNumberOfFreeBytes)
			*TotalNumberOfFreeBytes = env->GetLongField(jdiskFreeSpace, totalNumberOfFreeBytesID);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jdiskFreeSpace != NULL) env->DeleteLocalRef(jdiskFreeSpace);
	} catch(const char* msg) {
		DbgPrint(L"[OnGetDiskFreeSpace] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);

}

// see Win32 API GetVolumeInformation
NTSTATUS DOKAN_CALLBACK OnGetVolumeInformation(
	LPWSTR		VolumeNameBuffer,
	DWORD		VolumeNameSize,
	LPDWORD		VolumeSerialNumber,
	LPDWORD		MaximumComponentLength,
	LPDWORD		FileSystemFlags,
	LPWSTR		FileSystemNameBuffer,
	DWORD		FileSystemNameSize,
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnGetVolumeInformation]\n");
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jstring jvolumeName = ToJavaString(env, L"dokan");
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		jobject jvolumeInfo= env->CallObjectMethod(gOperations, onGetVolumeInformationID, jvolumeName, jdokanFileInfo);
		result = GetOperationResult(env);

		if (VolumeSerialNumber)
			*VolumeSerialNumber = env->GetIntField(jvolumeInfo, volumeSerialNumberID);
		if (MaximumComponentLength)
			*MaximumComponentLength = env->GetIntField(jvolumeInfo, maximumComponentLengthID);
		if (FileSystemFlags)
			*FileSystemFlags = env->GetIntField(jvolumeInfo, fileSystemFlagsID);

		// VolumeName, FileSystemName
		CopyStringField(env, jvolumeInfo, volumeNameID, VolumeNameBuffer, VolumeNameSize);
		CopyStringField(env, jvolumeInfo, fileSystemNameID, FileSystemNameBuffer, FileSystemNameSize);
		if (jvolumeName != NULL) env->DeleteLocalRef(jvolumeName);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
		if (jvolumeInfo != NULL) env->DeleteLocalRef(jvolumeInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnGetVolumeInformation] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);

}

NTSTATUS DOKAN_CALLBACK OnUnmount(
	PDOKAN_FILE_INFO DokanFileInfo)
{
	DbgPrint(L"[OnUnmount]\n");
	JNIEnv* env = get_env();
	//jvm->AttachCurrentThread((void **)&env, NULL);

	int result = -ERROR_GEN_FAILURE;
	try {
		jobject jdokanFileInfo = ToDokanFileInfoJavaObject(env, DokanFileInfo);
		
		env->CallVoidMethod(gOperations, onUnmountID, jdokanFileInfo);
		result = GetOperationResult(env);
		if (jdokanFileInfo != NULL) env->DeleteLocalRef(jdokanFileInfo);
	} catch(const char* msg) {
		DbgPrint(L"[OnUnmount] %s\n", msg);
	}

	release_env(env);
	return  ToNtStatus(result);
}

///*
// * Class:     net_decasdev_dokan_Dokan
// * Method:    unmount
// * Signature: (C)Z
// */
//JNIEXPORT jboolean JNICALL Java_net_decasdev_dokan_Dokan_unmount
//  (JNIEnv *, jclass, jchar jdriveLetter)
//{
//	return DokanUnmount(jdriveLetter);
//}

/*
 * Class:     net_decasdev_dokan_Dokan
 * Method:    removeMountPoint
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jboolean JNICALL Java_net_decasdev_dokan_Dokan_removeMountPoint
  (JNIEnv *env, jclass, jstring jMountPoint)
{
		int len = env->GetStringLength(jMountPoint);
		const jchar* chars = env->GetStringChars(jMountPoint, NULL);
		wchar_t* wsz = new wchar_t[len+1];
		memcpy(wsz, chars, len*2);
	    wsz[len] = 0;
		BOOL result = DokanRemoveMountPoint(wsz);
		env->ReleaseStringChars(jMountPoint, chars);
		env->DeleteGlobalRef(gOperations);
		gOperations = NULL;
	return result;
}

/*
 * Class:     net_decasdev_dokan_Dokan
 * Method:    isNameInExpression
 * Signature: (Ljava/lang/String;Ljava/lang/String;Z)Z
 */
JNIEXPORT jboolean JNICALL Java_net_decasdev_dokan_Dokan_isNameInExpression
  (JNIEnv *env, jclass, jstring jexpression, jstring jname, jboolean jignoreCase)
{
	try {
		const jchar* pExp = env->GetStringChars(jexpression, NULL);
		if (pExp == NULL) 
			throw "Failed at GetStringChars for expression";

		const jchar* pName = env->GetStringChars(jname, NULL);
		if (pName == NULL)
			throw "Failed at GetStringChars for name";

		jboolean result = DokanIsNameInExpression((LPCWSTR)pExp, (LPCWSTR)pName, jignoreCase);

		env->ReleaseStringChars(jexpression, pExp);
		env->ReleaseStringChars(jname, pName);

		return result;
	} catch(const char* msg) {
		env->ThrowNew(env->FindClass("java/lang/IllegalArgumentException"), msg);
		return FALSE;
	}
}

/*
 * Class:     net_decasdev_dokan_Dokan
 * Method:    getVersion
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_net_decasdev_dokan_Dokan_getVersion
  (JNIEnv *env, jclass)
{
	return DokanVersion();
}

/*
 * Class:     net_decasdev_dokan_Dokan
 * Method:    getDriverVersion
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_net_decasdev_dokan_Dokan_getDriverVersion
  (JNIEnv *env, jclass)
{
	return DokanDriverVersion();
}

JNIEXPORT jboolean JNICALL Java_net_decasdev_dokan_Dokan_resetTimeout(JNIEnv *env,jclass,
	jlong				timeout,	// timeout in millisecond
	jobject jfileinfo ) {
	DbgPrint(L"[resetTimeout]" );
	try {
		DOKAN_FILE_INFO dokanFileInfo;
		DbgPrint(L"[1]\n");
		ZeroMemory(&dokanFileInfo, sizeof(DOKAN_FILE_INFO));
		DbgPrint(L"[2]\n");
		dokanFileInfo.Context=env->GetLongField(jfileinfo, handle);
		DbgPrint(L"[3]\n");
		dokanFileInfo.ProcessId=env->GetIntField(jfileinfo, processId);
		DbgPrint(L"[4]\n");
		dokanFileInfo.DokanContext=env->GetLongField(jfileinfo, dokanContext);
		DbgPrint(L"[5] info= %d %d %d\n", dokanFileInfo.Context, dokanFileInfo.ProcessId, dokanFileInfo.DokanContext);
		return DokanResetTimeout((ULONG)timeout,&dokanFileInfo);
	}
	catch (const char* msg) {
		DbgPrint(L"[resetTimeout] %s\n", msg);
	}
	}


JNIEnv *get_env()
{
   JNIEnv *env;
   JavaVMAttachArgs args;

   args.version = JNI_VERSION_1_4;
   args.name = NULL;
   args.group = NULL;

   // a GCJ 4.0 bug workarround (supplied by Alexander Bostrm <abo@stacken.kth.se>)
   //if ((*vm)->GetEnv(vm, (void**)&env, args.version) == JNI_OK)
   //   return env;

   //TRACE("will attach thread");
   // attach thread as daemon thread so that JVM can exit after unmounting the fuseFS
   (*jvm).AttachCurrentThreadAsDaemon((void**)&env, (void*)&args);

   //(*vm)->AttachCurrentThread(vm, (void**)&env, (void*)&args);
   //printf("did attach thread to env: %p \n", env);
   return env;
}

void release_env(JNIEnv *env)
{
  
}
