/*
 * Copyright (c) 2013 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc. 11001 Bren Road East, Minnetonka, MN 55343
 * =======================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include "connector_api.h"
#include "platform.h"
#include "connector_config.h"
#include "connector_debug.h"

#if !defined CONNECTOR_FILE_SYSTEM 
#error "Please define CONNECTOR_FILE_SYSTEM in connector_config.h to run this sample" 
#endif

#if CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH > 460
#error The maximum supported CONNECTOR_FILE_SYSTEM_MAX_PATH_LENGTH is 460
#endif

/* 
 * To support large files (> 2 gigabytes) please: 
 * 1. Define CONNECTOR_FILE_SYSTEM_HAS_LARGE_FILES in connector_config.h 
 * 2. On a linux system with 32 bit architecture add define _FILE_OFFSET_BITS=64 in the 
 *    Makefile: 
 *          CFLAGS += -D_FILE_OFFSET_BITS=64 
 */ 
#if (defined CONNECTOR_SUPPORTS_64_BIT_INTEGERS)
#define CONNECTOR_OFFSET_MAX INT64_MAX
#define PRIoffset  PRId64
#else
#define CONNECTOR_OFFSET_MAX INT32_MAX
#define PRIoffset  PRId32
#endif


#if defined APP_ENABLE_MD5
#include <openssl/md5.h>

#define APP_MD5_BUFFER_SIZE 1024

typedef struct
{
    MD5_CTX md5;
    char buf[APP_MD5_BUFFER_SIZE];
    unsigned int flags;
    int fd;

} app_md5_ctx;
#endif

#ifndef APP_MIN_VALUE
#define APP_MIN_VALUE(a,b) (((a)<(b))?(a):(b))
#endif

typedef struct
{
    DIR * dirp;
    struct dirent dir_entry;

} app_dir_data_t;


static connector_callback_status_t app_process_file_error(connector_filesystem_errnum_t * const error_token, long int const errnum)
{
    connector_callback_status_t status;

    switch(errnum)
    {
    #if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
    #endif
        case EAGAIN:
            status = connector_callback_busy;
            break;

        default:
            status = connector_callback_error;
            *error_token = errnum;
            break;
    }
    return status;
}

static int app_convert_file_open_mode(int const oflag)
{
#if (CONNECTOR_FILE_O_RDONLY == O_RDONLY) && (CONNECTOR_FILE_O_WRONLY == O_WRONLY) && (CONNECTOR_FILE_O_RDWR == O_RDWR) && \
    (CONNECTOR_FILE_O_CREAT == O_CREAT)   && (CONNECTOR_FILE_O_APPEND == O_APPEND) && (CONNECTOR_FILE_O_TRUNC == O_TRUNC)

    return oflag;
#else
    int result = 0;

    if (oflag & CONNECTOR_FILE_O_WRONLY) result |= O_WRONLY;
    if (oflag & CONNECTOR_FILE_O_RDWR)   result |= O_RDWR;
    if (oflag & CONNECTOR_FILE_O_APPEND) result |= O_APPEND;
    if (oflag & CONNECTOR_FILE_O_CREAT)  result |= O_CREAT;
    if (oflag & CONNECTOR_FILE_O_TRUNC)  result |= O_TRUNC;

    if ((oflag & (CONNECTOR_FILE_O_WRONLY | CONNECTOR_FILE_O_RDWR)) == 0)
        result |= O_RDONLY;

    return result;
#endif
}

static connector_callback_status_t app_process_file_get_error(connector_file_system_get_error_t * const data)
{
    long int errnum = (long int)data->errnum;

    data->bytes_used = 0;

    if (errnum != 0)
    {
        char * err_str = strerror(errnum);

        data->bytes_used = APP_MIN_VALUE(strlen(err_str), data->bytes_available);
        memcpy(data->buffer, err_str, data->bytes_used);
    }

    switch(errnum)
    {
        case EACCES:
        case EPERM:
        case EROFS:
            data->error_status = connector_file_system_permission_denied;
            break;

        case ENOMEM:
        case ENAMETOOLONG:
            data->error_status = connector_file_system_out_of_memory;
            break;

        case ENOENT:
        case ENODEV:
        case EBADF:
            data->error_status = connector_file_system_path_not_found;
            break;

        case EINVAL:
        case ENOSYS:
        case ENOTDIR:
        case EISDIR:
            data->error_status = connector_file_system_invalid_parameter;
            break;

        case ENOSPC:
            data->error_status = connector_file_system_insufficient_storage_space;
            break;

        default:
            data->error_status = connector_file_system_unspec_error;
            break;
    }

    return connector_callback_continue;
}


#if defined APP_ENABLE_MD5
static app_md5_ctx * app_allocate_md5_ctx(unsigned int const flags)
{
    app_md5_ctx * ctx = malloc(sizeof *ctx);

    if (ctx != NULL)
    {
        ctx->flags = flags;
        ctx->fd    = -1;
    }
    else
    {
        APP_DEBUG("app_allocate_md5_ctx: malloc fails\n");
    }
    return ctx;
}

static connector_callback_status_t app_process_file_session_error(connector_file_system_session_error_t * const data)
{
     APP_DEBUG("Session Error %d\n", data->session_error);

    /* All application resources, used in the session, must be released in this callback */
    if (data->user_context != NULL)
    {
        app_md5_ctx * ctx = data->user_context;

        if (ctx->fd >= 0)
            close(ctx->fd);

        free(data->user_context);
        data->user_context = NULL;
    }
    return connector_callback_continue;
}

static connector_callback_status_t app_process_file_hash(connector_file_system_hash_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    app_md5_ctx * ctx = data->user_context;
    int ret;

    if (ctx == NULL)
    {
        ASSERT(0);
        goto error;
    }

    if (ctx->fd < 0)
    {
        ctx->fd = open(data->path, O_RDONLY);
        APP_DEBUG("Open %s, returned %d\n", data->path, ctx->fd);

        if (ctx->fd < 0)
        {
            ASSERT(0);
            goto error;
        }

        MD5_Init(&ctx->md5);
    }

    while ((ret = read (ctx->fd, ctx->buf, sizeof ctx->buf)) > 0)
    {
        MD5_Update(&ctx->md5, ctx->buf, ret);
    }
    if (ret == -1 && errno == EAGAIN)
    {
        status = connector_callback_busy;
        goto done;
    }

    APP_DEBUG("Close %d\n", ctx->fd);
    close (ctx->fd);
    ctx->fd = -1;

    if (ret == 0)
    {
        MD5_Final (data->hash_value, &ctx->md5);
        goto done;
    }

error:
    memset(data->hash_value, 0, data->bytes_requested);

done:
    if (ctx != NULL && status == connector_callback_continue)
    {
        /* free md5 context here,  if ls was issued a single file */
        if ((ctx->flags == connector_file_system_file_type_is_dir) == 0)
        {
            free(data->user_context);
            data->user_context = NULL;
        }
    }
    return status;
}
#else

static connector_callback_status_t app_process_file_session_error(connector_file_system_session_error_t * const data)
{
    UNUSED_ARGUMENT(data);
    APP_DEBUG("Session Error %d\n", data->session_error);

    /* All application resources, used in the session, must be released in this callback */
    return connector_callback_continue;
}

static connector_callback_status_t app_process_file_hash(connector_file_system_hash_t * const data)
{

    /* app_process_file_hash() should not be called if APP_ENABLE_MD5 is not defined */
    ASSERT(0);

    memset(data->hash_value, 0, data->bytes_requested);
    return connector_callback_continue;
}
#endif

static int app_copy_statbuf(connector_file_system_statbuf_t * const pstat, struct stat const * const statbuf)
{
    pstat->last_modified = (uint32_t) statbuf->st_mtime;
    int result = 0;

    if (S_ISDIR(statbuf->st_mode))
    {
        pstat->flags = connector_file_system_file_type_is_dir;
    }
    else
    if (S_ISREG(statbuf->st_mode))
    {
        if (statbuf->st_size <= CONNECTOR_OFFSET_MAX)
        {
            pstat->flags = connector_file_system_file_type_is_reg;
            pstat->file_size = (connector_file_offset_t) statbuf->st_size;
        }
        else
        {
            result = -1;
            errno = EOVERFLOW;
        }
    }
    return result;
}

static connector_callback_status_t app_process_file_stat(connector_file_system_stat_t * const data)
{
    struct stat statbuf;
    connector_file_system_statbuf_t * const pstat = &data->statbuf;
    connector_callback_status_t status = connector_callback_continue;

    int result = stat(data->path, &statbuf);

    if (result == 0) 
        result = app_copy_statbuf(pstat, &statbuf);

    if (result < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
        APP_DEBUG("stat for %s returned %d, errno %d\n", data->path, result, errno);

        if (errno == EOVERFLOW)
            APP_DEBUG("Please define CONNECTOR_FILE_SYSTEM_HAS_LARGE_FILES\n");
        goto done;
    }

    data->hash_algorithm.actual = connector_file_system_hash_none;

#if defined APP_ENABLE_MD5
    switch (data->hash_algorithm.requested)
    {
        case connector_file_system_hash_best:
        case connector_file_system_hash_md5:
            if (pstat->flags != connector_file_system_file_type_none)
            {
                data->hash_algorithm.actual = connector_file_system_hash_md5;
                if (data->user_context == NULL)
                {
                    data->user_context = app_allocate_md5_ctx(pstat->flags);
                    if (data->user_context == NULL)
                    {
                        status = app_process_file_error(&data->errnum, ENOMEM);
                    }
                }
            }
            break;

        default:
            break;
    }
#endif
    APP_DEBUG("stat for %s: file_size %"PRIoffset", last_modified %u\n", data->path, pstat->file_size, pstat->last_modified);
    
done:
    return status;
}


static connector_callback_status_t app_process_file_stat_dir_entry(connector_file_system_stat_dir_entry_t * const data)
{
    struct stat statbuf;
    connector_callback_status_t status = connector_callback_continue;
    connector_file_system_statbuf_t * const pstat = &data->statbuf;

    int result = stat(data->path, &statbuf);
    if (result == 0)
        result = app_copy_statbuf(pstat, &statbuf);

    if (result < 0)
    {
        /* don't return an error to avoid returning error back to device cloud
           for the whole directory, since there is no way to return an error for
           a single entry. Return zeroed status information instead.
        */
        APP_DEBUG("stat for %s returned %d, errno %d\n", data->path, result, errno);

        if (errno == EOVERFLOW)
            APP_DEBUG("Please define CONNECTOR_FILE_SYSTEM_HAS_LARGE_FILES\n");
        goto done;
    }

    APP_DEBUG("stat for %s: file_size %"PRIoffset", last_modified %u\n", data->path, pstat->file_size, pstat->last_modified);

done:
    return status;
}

static connector_callback_status_t app_process_file_opendir(connector_file_system_opendir_t * const data)
{

    connector_callback_status_t status = connector_callback_continue;
    DIR * dirp;

    errno = 0;
    dirp = opendir(data->path);

    if (dirp != NULL)
    {
        app_dir_data_t * dir_data = malloc (sizeof *dir_data);

        if (dir_data != NULL)
        {
            data->handle = dir_data;

            dir_data->dirp = dirp;
            APP_DEBUG("opendir for %s returned %p\n", data->path, (void *) dirp);
        }
        else
        {
            APP_DEBUG("app_process_file_opendir: malloc fails %s\n", data->path);
            status = app_process_file_error(&data->errnum, ENOMEM);
            closedir(dirp);
        }
    }
    else
        status = app_process_file_error(&data->errnum, errno);

    return status;
}

static connector_callback_status_t app_process_file_closedir(connector_file_system_closedir_t * const data)
{
    app_dir_data_t * dir_data = (app_dir_data_t *)data->handle;

    ASSERT(dir_data != NULL);
    APP_DEBUG("closedir %p\n", (void *) dir_data->dirp);

    closedir(dir_data->dirp);
    free(dir_data);

    /* All application resources, used in the session, must be released in this callback */

#if defined APP_ENABLE_MD5
    if (data->user_context != NULL)
    {
        /* free md5 context here, if ls was issued a directory */
        free(data->user_context);
        data->user_context = NULL;
    }
#endif
    return connector_callback_continue;
}

static connector_callback_status_t app_process_file_readdir(connector_file_system_readdir_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    app_dir_data_t * dir_data = (app_dir_data_t *)data->handle;
    struct dirent  * result = NULL;

    /* Read next directory entry */
    int rc = readdir_r(dir_data->dirp, &dir_data->dir_entry, &result);

    /* error */
    if (rc != 0)
    {
        status = app_process_file_error(&data->errnum, rc);
        APP_DEBUG("readdir_r returned %d\n", rc);
        *data->entry_name = '\0';
        goto done;
    }

    /* finished with the directory */
    if (result == NULL)
    {
        APP_DEBUG("No more directory entries %d\n", rc);
        goto done;
    }

    /* read valid entry */
    {
        size_t const name_len = strlen(result->d_name);

        APP_DEBUG("readdir_r returned directory entry name %s\n", result->d_name);

        if(name_len < data->bytes_available)
        {
            memcpy(data->entry_name, result->d_name, name_len + 1);
        }
        else
        {
            APP_DEBUG("directory entry name too long\n");
            status = app_process_file_error(&data->errnum, ENAMETOOLONG);
        }
    }

done:
    return status;
}


static connector_callback_status_t app_process_file_open(connector_file_system_open_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    int const oflag = app_convert_file_open_mode(data->oflag);

    /* 0664 = read,write owner + read,write group + read others */
    long int const fd = open(data->path, oflag, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);

    if (fd < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
    }

    APP_DEBUG("Open file %s, %d, returned %ld", data->path, oflag, fd);
    if (fd < 0)
        APP_DEBUG(", errno %d", errno);
    APP_DEBUG("\n");

    data->handle = fd;

    return status;
}


static connector_callback_status_t app_process_file_lseek(connector_file_system_lseek_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;
    int  origin;
    off_t result;

    switch(data->origin)
    {
        case connector_file_system_seek_set:
            origin = SEEK_SET;
            break;

        case connector_file_system_seek_end:
            origin = SEEK_END;
            break;

        case connector_file_system_seek_cur:
        default:
            origin = SEEK_CUR;
            break;
    }

    result = lseek(fd, data->requested_offset, origin);
    if (result < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
    }
    data->resulting_offset = (connector_file_offset_t) result;

    APP_DEBUG("lseek fd %ld, offset %"PRIoffset", origin %d returned %"PRIoffset,
                fd, data->requested_offset, data->origin, data->resulting_offset);

    if (result < 0) 
        APP_DEBUG(", errno %d\n",errno);
    else 
        APP_DEBUG("\n");

    return status;
}

static connector_callback_status_t app_process_file_ftruncate(connector_file_system_truncate_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;

    int const result = ftruncate(fd, data->length_in_bytes);

    if (result < 0)
    {
        APP_DEBUG("ftruncate fd %ld, %"PRIoffset" returned %d, errno %d\n", fd, data->length_in_bytes, result,  errno);
        status = app_process_file_error(&data->errnum, errno);
    }
    else
        APP_DEBUG("ftruncate fd %ld, %"PRIoffset"\n", fd, data->length_in_bytes);

    return status;
}

static connector_callback_status_t app_process_file_remove(connector_file_system_remove_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;

    int const result = unlink(data->path);

    if (result < 0)
    {
        APP_DEBUG("unlink file %s returned %d, errno %d\n", data->path, result, errno);
        status = app_process_file_error(&data->errnum, errno);
    }
    else
        APP_DEBUG("unlink file %s\n", data->path);

    return status;
}

static connector_callback_status_t app_process_file_read(connector_file_system_read_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;

    int const result = read(fd, data->buffer, data->bytes_available);

    if (result < 0)
    {
        APP_DEBUG("read fd %ld, %" PRIsize ", returned %d, errno %d\n", fd, data->bytes_available, result, errno);
        status = app_process_file_error(&data->errnum, errno);
        goto done;
    }

    APP_DEBUG("read fd %ld, %" PRIsize ", returned %d\n", fd, data->bytes_available, result);
    data->bytes_used = result;

done:
    return status;
}

static connector_callback_status_t app_process_file_write(connector_file_system_write_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;

    int const result = write(fd, data->buffer, data->bytes_available);

    if (result < 0)
    {
        APP_DEBUG("write fd %ld, %" PRIsize ", returned %d, errno %d\n", fd, data->bytes_available, result, errno);
        status = app_process_file_error(&data->errnum, errno);
        goto done;
    }
    APP_DEBUG("write fd %ld, %" PRIsize ", returned %d\n", fd, data->bytes_available, result);

    data->bytes_used = result;

done:
    return status;
}

static connector_callback_status_t app_process_file_close(connector_file_system_close_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;
    int const result = close(fd);

    if (result < 0)
    {
        APP_DEBUG("close fd %ld returned %d, errno %d\n", fd, result, errno);
        if (errno == EIO) 
            status = app_process_file_error(&data->errnum, EIO);
    }
    else
        APP_DEBUG("close fd %ld\n", fd);

    /* All application resources, used in the session, must be released in this callback */

    return status;
}

typedef enum 
{
    action_none,
    return_abort,
    return_busy,
    return_unrecognized,
    return_invalid_code,
    set_io_error,
    set_io_error_no_errno,
    set_null_handle,
    set_zero_datalength,
    set_invalid_datalength,
    set_invalid_data,
    partial_process,
    partial_process2,
    set_file_flags_zero

} test_action_t;

typedef enum{
    no_cleanup,
    do_cleanup
} dvt_cleanup_type_t;

static struct 
{
 
    char * path;
    int    callback_cnt;
    dvt_cleanup_type_t cleanup;
    connector_request_id_file_system_t callback_id;
    test_action_t  action;

} test_table[] = {

    { "dvt_fs_stat1_abort",             1, do_cleanup, connector_request_id_file_system_stat, return_abort},
    { "dvt_fs_stat1_unrecognized",      1, do_cleanup, connector_request_id_file_system_stat, return_unrecognized},
    { "dvt_fs_stat1_retinvalid",        1, do_cleanup, connector_request_id_file_system_stat, return_invalid_code},
    { "dvt_fs_stat1_io_error",          1, do_cleanup, connector_request_id_file_system_stat, set_io_error},
    { "dvt_fs_stat1_io_error_no_errno", 1, do_cleanup, connector_request_id_file_system_stat, set_io_error_no_errno},
    { "dvt_fs_stat1_busy",              1, no_cleanup, connector_request_id_file_system_stat, return_busy},
    { "dvt_fs_stat1_not_regdir",        1, do_cleanup, connector_request_id_file_system_stat, set_file_flags_zero},
    { "dvt_fs_stat1_badhash",           1, do_cleanup, connector_request_id_file_system_stat, set_invalid_data},

    { "dvt_fs_opendir_abort",             1, do_cleanup, connector_request_id_file_system_opendir, return_abort},
    { "dvt_fs_opendir_unrecognized",      1, do_cleanup, connector_request_id_file_system_opendir, return_unrecognized},
    { "dvt_fs_opendir_retinvalid",        1, do_cleanup, connector_request_id_file_system_opendir, return_invalid_code},
    { "dvt_fs_opendir_null_handle",       1, do_cleanup, connector_request_id_file_system_opendir, set_null_handle},
    { "dvt_fs_opendir_io_error",          1, do_cleanup, connector_request_id_file_system_opendir, set_io_error},
    { "dvt_fs_opendir_io_error_no_errno", 1, do_cleanup, connector_request_id_file_system_opendir, set_io_error_no_errno},
    { "dvt_fs_opendir_busy",              1, no_cleanup, connector_request_id_file_system_opendir, return_busy},
    
 
    { "dvt_fs_readdir_abort",             1, no_cleanup, connector_request_id_file_system_readdir, return_abort},
    { "dvt_fs_readdir_abort2",            2, no_cleanup, connector_request_id_file_system_readdir, return_abort},
    { "dvt_fs_readdir_unrecognized",      1, no_cleanup, connector_request_id_file_system_readdir, return_unrecognized},
    { "dvt_fs_readdir_retinvalid",        1, no_cleanup, connector_request_id_file_system_readdir, return_invalid_code},
    { "dvt_fs_readdir_io_error",          1, no_cleanup, connector_request_id_file_system_readdir, set_io_error},
    { "dvt_fs_readdir_io_error2",         3, no_cleanup, connector_request_id_file_system_readdir, set_io_error},
    { "dvt_fs_readdir_io_error_no_errno", 1, no_cleanup, connector_request_id_file_system_readdir, set_io_error_no_errno},
    { "dvt_fs_readdir_busy",              1, no_cleanup, connector_request_id_file_system_readdir, return_busy},
    { "dvt_fs_readdir_busy2",             2, no_cleanup, connector_request_id_file_system_readdir, return_busy},
    { "dvt_fs_readdir_bad_datalength",    1, no_cleanup, connector_request_id_file_system_readdir, set_invalid_datalength},
    { "dvt_fs_readdir_zero_datalength",   1, no_cleanup, connector_request_id_file_system_readdir, set_zero_datalength},
                                             
    { "dvt_fs_stat3_abort",             2, no_cleanup, connector_request_id_file_system_stat_dir_entry, return_abort},
    { "dvt_fs_stat3_unrecognized",      2, no_cleanup, connector_request_id_file_system_stat_dir_entry, return_unrecognized},
    { "dvt_fs_stat3_retinvalid",        2, no_cleanup, connector_request_id_file_system_stat_dir_entry, return_invalid_code},
    { "dvt_fs_stat2_io_error",          1, no_cleanup, connector_request_id_file_system_stat_dir_entry, set_io_error},
    { "dvt_fs_stat2_io_error_no_errno", 1, no_cleanup, connector_request_id_file_system_stat_dir_entry, set_io_error_no_errno},
    { "dvt_fs_stat3_io_error",          2, no_cleanup, connector_request_id_file_system_stat_dir_entry, set_io_error},
    { "dvt_fs_stat3_io_error_no_errno", 2, no_cleanup, connector_request_id_file_system_stat_dir_entry, set_io_error_no_errno},
    { "dvt_fs_stat3_busy",              2, no_cleanup, connector_request_id_file_system_stat_dir_entry, return_busy},


    { "dvt_fs_hash_abort",             1, no_cleanup, connector_request_id_file_system_hash, return_abort},
    { "dvt_fs_hash_unrecognized",      1, no_cleanup, connector_request_id_file_system_hash, return_unrecognized},
    { "dvt_fs_hash_retinvalid",        1, no_cleanup, connector_request_id_file_system_hash, return_invalid_code},
    { "dvt_fs_hash_io_error",          2, no_cleanup, connector_request_id_file_system_hash, set_io_error},
    { "dvt_fs_hash_io_error_no_errno", 2, no_cleanup, connector_request_id_file_system_hash, set_io_error_no_errno},
    { "dvt_fs_hash_busy",              1, no_cleanup, connector_request_id_file_system_hash, return_busy},

    { "dvt_fs_hash_file_abort",             1, do_cleanup, connector_request_id_file_system_hash, return_abort},
    { "dvt_fs_hash_file_unrecognized",      1, do_cleanup, connector_request_id_file_system_hash, return_unrecognized},
    { "dvt_fs_hash_file_retinvalid",        1, do_cleanup, connector_request_id_file_system_hash, return_invalid_code},
    { "dvt_fs_hash_file_io_error",          1, do_cleanup, connector_request_id_file_system_hash, set_io_error},
    { "dvt_fs_hash_file_io_error_no_errno", 1, do_cleanup, connector_request_id_file_system_hash, set_io_error_no_errno},
    { "dvt_fs_hash_file_busy",              1, no_cleanup, connector_request_id_file_system_hash, return_busy},

    { "dvt_fs_strerr_abort",            2, do_cleanup, connector_request_id_file_system_get_error, return_abort},
    { "dvt_fs_strerr_bad_datalen",      2, do_cleanup, connector_request_id_file_system_get_error, set_invalid_datalength},
    { "dvt_fs_strerr_retinvalid",       2, do_cleanup, connector_request_id_file_system_get_error, return_invalid_code},
    { "dvt_fs_strerr_zero_datalen",     2, do_cleanup, connector_request_id_file_system_get_error, set_zero_datalength},

    { "dvt_fs_closedir_abort",             1, do_cleanup, connector_request_id_file_system_closedir, return_abort},
    { "dvt_fs_closedir_busy",              1, no_cleanup, connector_request_id_file_system_closedir, return_busy},
    { "dvt_fs_closedir_unrecognized",      1, do_cleanup, connector_request_id_file_system_closedir, return_unrecognized},
    { "dvt_fs_closedir_retinvalid",        1, do_cleanup, connector_request_id_file_system_closedir, return_invalid_code},
    { "dvt_fs_closedir_io_error",          1, do_cleanup, connector_request_id_file_system_closedir, set_io_error},
    { "dvt_fs_closedir_io_error_no_errno", 1, do_cleanup, connector_request_id_file_system_closedir, set_io_error_no_errno},

    { "dvt_fs_rm_abort",             1, do_cleanup, connector_request_id_file_system_remove, return_abort},
    { "dvt_fs_rm_busy",              1, no_cleanup, connector_request_id_file_system_remove, return_busy},
    { "dvt_fs_rm_unrecognized",      1, do_cleanup, connector_request_id_file_system_remove, return_unrecognized},
    { "dvt_fs_rm_retinvalid",        1, do_cleanup, connector_request_id_file_system_remove, return_invalid_code},
    { "dvt_fs_rm_io_error",          1, do_cleanup, connector_request_id_file_system_remove, set_io_error},
    { "dvt_fs_rm_io_error_no_errno", 1, do_cleanup, connector_request_id_file_system_remove, set_io_error_no_errno},

    { "dvt_fs_truncate_abort",             1, no_cleanup, connector_request_id_file_system_ftruncate, return_abort},
    { "dvt_fs_truncate_busy",              1, no_cleanup, connector_request_id_file_system_ftruncate, return_busy},
    { "dvt_fs_truncate_unrecognized",      1, no_cleanup, connector_request_id_file_system_ftruncate, return_unrecognized},
    { "dvt_fs_truncate_retinvalid",        1, no_cleanup, connector_request_id_file_system_ftruncate, return_invalid_code},
    { "dvt_fs_truncate_io_error",          1, no_cleanup, connector_request_id_file_system_ftruncate, set_io_error},
    { "dvt_fs_truncate_io_error_no_errno", 1, no_cleanup, connector_request_id_file_system_ftruncate, set_io_error_no_errno},

};

typedef enum
{
    dir_test_type,
    file_ls_test_type,
    rm_test_type,
    truncate_test_type
} dvt_test_t;

static struct 
{
    char filename[256];
    int  callback_cnt;
    int  new_test;
    dvt_cleanup_type_t cleanup;
    dvt_test_t test_type;
    
} dvt_data = {"", 0, 1, 0};

static void dvt_init_test(char const * name)
{
    strcpy(dvt_data.filename, name);

    dvt_data.new_test = 0;
    dvt_data.callback_cnt = 0;
    dvt_data.cleanup = no_cleanup;
    dvt_data.test_type = dir_test_type;
    if (strstr(name, "dvt_fs_hash_file")) 
       dvt_data.test_type = file_ls_test_type;
    else
    if (strstr(name, "dvt_fs_rm")) 
       dvt_data.test_type = rm_test_type;
    else
    if (strstr(name, "dvt_fs_truncate")) 
       dvt_data.test_type = truncate_test_type;

    APP_DEBUG("dvt_init_test: %s\n", name);
}

static void dvt_cleanup_test(void)
{
    dvt_data.new_test = 1;
    dvt_data.cleanup = no_cleanup;
    dvt_data.test_type = dir_test_type;
    APP_DEBUG("dvt_cleanup_test\n");
}


static test_action_t dvt_find_test(connector_request_id_file_system_t const request_id,
                                   void * const data)
{

    test_action_t action = action_none;
    unsigned int i;

    if (dvt_data.new_test && request_id == connector_request_id_file_system_open)
    {
        connector_file_system_open_t const * pdata = data;
        char const * ptr;

        ptr = strstr(pdata->path, "dvt_fs_stat");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_opendir");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_readdir");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_hash");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_strerr");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_closedir");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_rm");
        if (ptr == NULL)
            ptr = strstr(pdata->path, "dvt_fs_truncate");

        if (ptr == NULL)
            goto done;

        dvt_init_test(ptr);
    }

    for (i = 0; i < sizeof test_table / sizeof test_table[0]; i++) 
    {
        if ((test_table[i].callback_id == request_id) && 
            strcmp(dvt_data.filename, test_table[i].path) == 0) 
        {
            dvt_data.callback_cnt++;
            if (dvt_data.callback_cnt == test_table[i].callback_cnt)
            {
                action = test_table[i].action;
                dvt_data.cleanup = test_table[i].cleanup;
            }
            APP_DEBUG("dvt_find_test,  request_id %d, action %d, callback_cnt %d\n", request_id, action, dvt_data.callback_cnt);
            break;
        }
    }

done:
    return action;
}

static int dvt_pre_test(connector_request_id_file_system_t const request_id,
                        void * const data,
                        connector_callback_status_t * status)
{
    const size_t MAX_DATA_LENGTH
= 20000;
    int result = -1;

    test_action_t action = dvt_find_test(request_id, data);

    switch (action)
    {
        case return_abort:
            *status = connector_callback_abort;
            break;

        case return_busy:
            *status = connector_callback_busy;
            break;
 
        case return_unrecognized:
            *status = connector_callback_unrecognized;
            break;

        case return_invalid_code:
            *status = (connector_callback_status_t) -1;
            break;

        case set_io_error:
        {
            connector_file_system_open_t * pdata = data;
            *status = app_process_file_error(&pdata->errnum, EACCES);
            break;
        }
        break;
    
        case set_io_error_no_errno:
        {
           connector_file_system_open_t * pdata = data;
           pdata->errnum = CONNECTOR_FILESYSTEM_ERRNUM_NONE;
           *status = connector_callback_error;
        }
        break;

        case set_null_handle:
             break;

        case set_zero_datalength:
        {
            switch(request_id) 
            {
                case connector_request_id_file_system_readdir:
                {
                    connector_file_system_readdir_t * pdata = data;
                    *pdata->entry_name = '\0';
                }
                break;
                case connector_request_id_file_system_get_error:
                {
                    connector_file_system_get_error_t * pdata = data;
                    pdata->bytes_used = 0;
                }
                break;
            default:
                ASSERT(connector_true);
                break;
            }
            break;
        }

        case set_invalid_datalength:
        {
            switch(request_id) 
            {
                case connector_request_id_file_system_readdir:
                {
                    connector_file_system_readdir_t * pdata = data;
                    memset(pdata->entry_name, 'a', pdata->bytes_available);
                }
                break;
                case connector_request_id_file_system_get_error:
                {
                    connector_file_system_get_error_t * pdata = data;
                    pdata->bytes_used = MAX_DATA_LENGTH;
                }
                break;
            default:
                ASSERT(connector_true);
                result = 0;
                break;
            }
            break;
        }

        case set_file_flags_zero:
        {
            switch (request_id) 
            {
                case connector_request_id_file_system_stat:
                {
                    connector_file_system_stat_t * pdata = data;
                    pdata->hash_algorithm.actual = connector_file_system_hash_none;
                    memset(&pdata->statbuf, 0, sizeof pdata->statbuf);
                    break;
                }
                case connector_request_id_file_system_stat_dir_entry:
                {
                    connector_file_system_stat_dir_entry_t * pdata = data;
                    memset(&pdata->statbuf, 0, sizeof pdata->statbuf);
                    break;
                }
                default:
                    ASSERT(connector_true);
                    result = 0;
                    break;
           }
           break;
        }

        case set_invalid_data:
            if (request_id == connector_request_id_file_system_stat)
            {
                connector_file_system_stat_t * pdata = data;
                memset(&pdata->statbuf, 0, sizeof pdata->statbuf);
                pdata->hash_algorithm.actual = 100;
            }
            else
            {
                 ASSERT(connector_true);
                 result = 0;
             }
    
        break;       

        case action_none:
        default:
            result = 0;
    }

    if (dvt_data.cleanup == do_cleanup)
    {
        dvt_cleanup_test();
    }
    return result;
}


connector_callback_status_t app_file_system_handler(connector_request_id_file_system_t const request,
                                                    void * const data)
{
    connector_callback_status_t status = connector_callback_continue;

    if (dvt_pre_test(request, data, &status) != 0)
        goto done;

    switch (request)
    {
        case connector_request_id_file_system_open:
            status = app_process_file_open(data);
            break;

        case connector_request_id_file_system_read:
            status = app_process_file_read(data);
            break;

        case connector_request_id_file_system_write:
            status = app_process_file_write(data);
            break;

        case connector_request_id_file_system_lseek:
            status = app_process_file_lseek(data);
            break;

        case connector_request_id_file_system_close:
            status = app_process_file_close(data);

            if (dvt_data.test_type == truncate_test_type && dvt_data.new_test == 0 && 
                status != connector_callback_busy) 
            {
                dvt_cleanup_test();
            }
            break;

        case connector_request_id_file_system_ftruncate:
            status = app_process_file_ftruncate(data);
            break;

        case connector_request_id_file_system_remove:
            status = app_process_file_remove(data);

            if (dvt_data.test_type == rm_test_type && dvt_data.new_test == 0 && 
                status != connector_callback_busy) 
            {
                dvt_cleanup_test();
            }
            break;

        case connector_request_id_file_system_stat:
            status = app_process_file_stat(data);
            break;

        case connector_request_id_file_system_stat_dir_entry:
            status = app_process_file_stat_dir_entry(data);
            break;

        case connector_request_id_file_system_opendir:
            status = app_process_file_opendir(data);
            break;

        case connector_request_id_file_system_readdir:
            status = app_process_file_readdir(data);
            break;

        case connector_request_id_file_system_closedir:
            status = app_process_file_closedir(data);

            if (dvt_data.test_type == dir_test_type && dvt_data.new_test == 0 && 
                status != connector_callback_busy) 
            {
                dvt_cleanup_test();
            }
            break;

        case connector_request_id_file_system_get_error:
            status = app_process_file_get_error(data);
            break;

        case connector_request_id_file_system_hash:
            status = app_process_file_hash(data);

            if (dvt_data.test_type == file_ls_test_type && dvt_data.new_test == 0 && 
                status != connector_callback_busy) 
            {
                dvt_cleanup_test();
            }
            break;

        case connector_request_id_file_system_session_error:
            status = app_process_file_session_error(data);
            break;

        default:
            status = connector_callback_unrecognized;
            APP_DEBUG("Unsupported file system request %d\n", request);
    }

done:
    return status;
}


