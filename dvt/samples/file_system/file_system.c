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
#include <time.h>
#include "connector_api.h"
#include "platform.h"

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

#define DVT_FS_BUSY_OFFSET      0
#define DVT_FS_START_OFFSET     1
#define DVT_FS_MIDDLE_OFFSET    2
#define DVT_FS_END_OFFSET       3
#define DVT_FS_TIMEOUT_OFFSET   4

#define DVT_FS_BUSY_SECS        10
#define DVT_FS_TIMEOUT_SECS     90


typedef enum
{
    dvt_fs_case_offset_busy,
    dvt_fs_case_offset_start,
    dvt_fs_case_offset_middle,
    dvt_fs_case_offset_end,
    dvt_fs_case_offset_timeout,
    dvt_fs_case_offset_COUNT
} dvt_fs_case_offset_t;

typedef enum
{
    dvt_fs_state_at_start,
    dvt_fs_state_at_middle,
    dvt_fs_state_at_end
} dvt_fs_state_t;

typedef enum
{
    dvt_fs_error_none,
    dvt_fs_error_get_busy,
    dvt_fs_error_get_start,
    dvt_fs_error_get_middle,
    dvt_fs_error_get_end,
    dvt_fs_error_get_timeout,
    dvt_fs_error_put_busy,
    dvt_fs_error_put_start,
    dvt_fs_error_put_middle,
    dvt_fs_error_put_end,
    dvt_fs_error_put_timeout,
    dvt_fs_error_ls_busy,
    dvt_fs_error_ls_start,
    dvt_fs_error_ls_middle,
    dvt_fs_error_ls_end,
    dvt_fs_error_ls_timeout,
    dvt_fs_error_ls_invalid_hash,
    dvt_fs_error_rm_timeout,
    dvt_fs_error_COUNT
} dvt_fs_error_cases_t;

typedef struct
{
    char const * fpath;
    dvt_fs_error_cases_t error_case;
}dvt_fs_error_entry_t;

static dvt_fs_error_entry_t dvt_fs_error_list[] =
{
    {"dvt_fs_get_error.test", dvt_fs_error_get_busy},
    {"dvt_fs_put_error.test", dvt_fs_error_put_busy},
    {"./public", dvt_fs_error_ls_busy},
    {"./public/step", dvt_fs_error_ls_start},
    {"./public/run", dvt_fs_error_ls_end},
    {"./public/run/samples", dvt_fs_error_ls_middle},
    {"./public/run/platforms", dvt_fs_error_ls_timeout},
    {"./public/include", dvt_fs_error_ls_invalid_hash},
    {"dvt_fs_rm_tout.test", dvt_fs_error_rm_timeout}
};

static size_t const  dvt_fs_error_list_count  = ARRAY_SIZE(dvt_fs_error_list);
static dvt_fs_error_cases_t dvt_current_error_case = dvt_fs_error_none;
static dvt_fs_state_t dvt_current_state = dvt_fs_state_at_start;

static void update_error_case(char const * const path)
{
    size_t i;

    dvt_current_error_case = dvt_fs_error_none;
    for (i = 0; i < dvt_fs_error_list_count; i++)
    {
        if (!strcmp(path, dvt_fs_error_list[i].fpath))
        {
            dvt_current_error_case = dvt_fs_error_list[i].error_case;
            break;
        }
    }
    dvt_current_state = dvt_fs_state_at_start;
}

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

    APP_DEBUG("app_process_file_get_error\n");

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

    // All application resources, used in the session, must be released in this callback
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
    update_error_case(data->path);


    if ((dirp != NULL) && (dvt_current_error_case == dvt_fs_error_ls_start))
    {
       closedir(dirp);
       status = app_process_file_error(&data->errnum, EACCES);
       goto done;
    }

    if (dirp != NULL)
    {
        app_dir_data_t * dir_data = malloc (sizeof *dir_data);

        if (dir_data != NULL)
        {
            data->handle = dir_data;

            dir_data->dirp = dirp;
            APP_DEBUG("opendir for %s returned %p\n", data->path, (void *) dirp);
            update_error_case(data->path);
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

done:
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

    switch (dvt_current_error_case)
    {
        case dvt_fs_error_ls_busy:
            if (dvt_current_state < dvt_fs_state_at_end)
            {
                status = connector_callback_busy;
                goto done;
            }
            break;

        case dvt_fs_error_ls_middle:
            if (dvt_current_state == dvt_fs_state_at_middle)
            {
                status = app_process_file_error(&data->errnum, EINVAL);
                goto done;
            }
            break;

        case dvt_fs_error_ls_end:
            if (dvt_current_state == dvt_fs_state_at_end)
            {
                status = app_process_file_error(&data->errnum, ENOMEM);
                goto done;
            }
            break;

        case dvt_fs_error_ls_timeout:
            {
                static time_t dvt_start_time;
                time_t dvt_current_time;

                if (dvt_current_state == dvt_fs_state_at_start)
                    time(&dvt_start_time);
            
                time(&dvt_current_time);

                if ((dvt_current_time - dvt_start_time) < DVT_FS_BUSY_SECS)
                    status = connector_callback_busy;
                else
                    status = app_process_file_error(&data->errnum, ETIMEDOUT);
                goto done;
            }
        default:
            break;
    }

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
    if (dvt_current_state < dvt_fs_state_at_end)
        dvt_current_state++;
    return status;
}


static connector_callback_status_t app_process_file_open(connector_file_system_open_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    int const oflag = app_convert_file_open_mode(data->oflag);

    /* 0664 = read,write owner + read,write group + read others */
    long int const fd = open(data->path, oflag, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
    APP_DEBUG("Open %s, %d, returned %ld\n", data->path, oflag, fd);

    update_error_case(data->path);


    if (fd < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
    }

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

    APP_DEBUG("lseek fd %ld, offset %"PRIoffset", origin %d returned %"PRIoffset,
                fd, data->requested_offset, data->origin, data->resulting_offset);

    if (result < 0) 
        APP_DEBUG(", errno %d\n",errno);
    else 
        APP_DEBUG("\n");

    data->resulting_offset = (connector_file_offset_t) result;

    if (data->resulting_offset < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
    }
    else
    {
        if (dvt_current_error_case != dvt_fs_error_none && 
            data->origin == connector_file_system_seek_set)
        {
            APP_DEBUG("Offset %"PRIoffset"\n",data->requested_offset);

            if (data->requested_offset < dvt_fs_case_offset_COUNT)
                dvt_current_error_case += data->requested_offset;
            else
            {
                APP_DEBUG("Unexpected offset %d for error case %"PRIoffset"\n", data->requested_offset, dvt_current_error_case);
            }
        }
    }

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
    update_error_case(data->path);
    static int cleanup = 0;

    if ((dvt_current_error_case == dvt_fs_error_rm_timeout) && (cleanup == 0))
    {
        static time_t dvt_start_time = 0;
        time_t dvt_current_time;

        if (dvt_start_time == 0)
        {
            time(&dvt_start_time);
        }

        time(&dvt_current_time);

        if ((dvt_current_time - dvt_start_time) < DVT_FS_BUSY_SECS)
        {
             status = connector_callback_busy;
        }
        else
        {
            dvt_start_time = 0;
            status = app_process_file_error(&data->errnum, ETIMEDOUT);
            cleanup = 1;
        }
        goto done;
    }
    cleanup = 0;

    int const result = unlink(data->path);

    APP_DEBUG("unlink %s returned %d\n", data->path, result);

    if (result < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
    }

done:
    return status;
}

static connector_callback_status_t app_process_file_read(connector_file_system_read_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;

    static time_t dvt_start_time;
    time_t dvt_current_time;

    switch (dvt_current_error_case)
    {
        case dvt_fs_error_get_busy:
            if (dvt_current_state < dvt_fs_state_at_end)
            {
                status = connector_callback_busy;
                goto done;
            }
            break;

        case dvt_fs_error_get_start:
            if (dvt_current_state == dvt_fs_state_at_start)
            {
                status = app_process_file_error(&data->errnum, EACCES);
                goto done;
            }
            break;

        case dvt_fs_error_get_middle:
            if (dvt_current_state == dvt_fs_state_at_middle)
            {
                status = app_process_file_error(&data->errnum, EINVAL);
                goto done;
            }
            break;

        case dvt_fs_error_get_end:
            if (dvt_current_state == dvt_fs_state_at_end)
            {
                status = app_process_file_error(&data->errnum, ENOMEM);
                goto done;
            }
            break;

        case dvt_fs_error_get_timeout:
            if (dvt_current_state == dvt_fs_state_at_start)
            {
                time(&dvt_start_time);
                break;
            }
            
            time(&dvt_current_time);

            if ((dvt_current_time - dvt_start_time) < DVT_FS_TIMEOUT_SECS)
            {
                status = connector_callback_busy;
                goto done;
            }
            else
            {
                APP_DEBUG("I have finished %d sec busy cycle and will perform read!!!\n", DVT_FS_TIMEOUT_SECS);
                break;
            }

        default:
            break;
    }

    int const result = read(fd, data->buffer, data->bytes_available);

    APP_DEBUG("read %ld, %" PRIsize ", returned %d\n", fd, data->bytes_available, result);

    if (result < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
        goto done;
    }

    data->bytes_used = result;

done:
    if (dvt_current_state < dvt_fs_state_at_end)
        dvt_current_state++;
    return status;
}


static connector_callback_status_t app_process_file_write(connector_file_system_write_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;
    static time_t dvt_start_time;
    time_t dvt_current_time;

    switch (dvt_current_error_case)
    {
    case dvt_fs_error_put_busy:

            if (dvt_current_state < dvt_fs_state_at_middle)
            {
                status = connector_callback_busy;
                goto done;
            }
            break;

        case dvt_fs_error_put_start:
            if (dvt_current_state == dvt_fs_state_at_start)
            {
                status = app_process_file_error(&data->errnum, EACCES);
                goto done;
            }
            break;

        case dvt_fs_error_put_middle:
            if (dvt_current_state == dvt_fs_state_at_middle)
            {
                status = app_process_file_error(&data->errnum, EINVAL);
                goto done;
            }
            break;

        case dvt_fs_error_put_end:
            if (dvt_current_state == dvt_fs_state_at_end)
            {
                status = app_process_file_error(&data->errnum, ENOMEM);
                goto done;
            }
            break;

        case dvt_fs_error_put_timeout:
            if (dvt_current_state == dvt_fs_state_at_start)
                time(&dvt_start_time);
            
            time(&dvt_current_time);

            if ((dvt_current_time - dvt_start_time) < DVT_FS_BUSY_SECS)
                status = connector_callback_busy;
            else
                status = app_process_file_error(&data->errnum, ETIMEDOUT);
            goto done;

        default:
            break;
    }


    int const result = write(fd, data->buffer, data->bytes_available);


    APP_DEBUG("write %ld, %" PRIsize ", returned %d\n", fd, data->bytes_available, result);

    if (result < 0)
    {
        status = app_process_file_error(&data->errnum, errno);
        goto done;
    }

    data->bytes_used = result;

done:
    if (dvt_current_state < dvt_fs_state_at_end)
        dvt_current_state++;
    return status;
}

static connector_callback_status_t app_process_file_close(connector_file_system_close_t * const data)
{
    connector_callback_status_t status = connector_callback_continue;
    long int const fd = (long int) data->handle;
    int const result = close(fd);

    if (result < 0 && errno == EIO)
    {
        status = app_process_file_error(&data->errnum, EIO);
    }

    APP_DEBUG("close %ld returned %d\n", fd, result);

    /* All application resources, used in the session, must be released in this callback */

    return status;
}

connector_callback_status_t app_file_system_handler(connector_request_id_file_system_t const request,
                                                    void * const data)
{
    connector_callback_status_t status = connector_callback_continue;

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
            break;

        case connector_request_id_file_system_ftruncate:
            status = app_process_file_ftruncate(data);
            break;

        case connector_request_id_file_system_remove:
            status = app_process_file_remove(data);
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
            break;

        case connector_request_id_file_system_get_error:
            status = app_process_file_get_error(data);
            break;

        case connector_request_id_file_system_hash:
            status = app_process_file_hash(data);
            break;

        case connector_request_id_file_system_session_error:
            status = app_process_file_session_error(data);
            break;

        default:
            status = connector_callback_unrecognized;
            APP_DEBUG("Unsupported file system request %d\n", request);
    }

    return status;
}

