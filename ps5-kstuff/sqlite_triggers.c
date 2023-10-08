#include <stddef.h>
#include <sys/mman.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
enum { SQLITE_OK = 0, SQLITE_ROW = 100, SQLITE_DONE = 101,  };
enum { SQLITE_OPEN_READWRITE = 2 };

struct buf
{
    char* data;
    size_t sz;
    size_t cap;
};

#define SQL_COMMANDS_PER_TABLE(PUTS, PUTN)\
PUTS("create trigger if not exists trig_update_drm_") PUTN() PUTS(" after update of appDrmType on ") PUTN() PUTS(" when new.appDrmType = 1 begin update ") PUTN() PUTS(" set appDrmType = 5 where titleId = old.titleId; end;")\
PUTS("create trigger if not exists trig_insert_drm_") PUTN() PUTS(" after insert on ") PUTN() PUTS(" when new.appDrmType = 1 begin update ") PUTN() PUTS(" set appDrmType = 5 where titleId = new.titleId; end;")\
PUTS("update ") PUTN() PUTS(" set appDrmType=5 where appDrmType=1;")

void log_table_name(struct buf* buf, const char* name)
{
    char* prefix = "tbl_iconinfo_";
    size_t i = 0;
    while(prefix[i] && prefix[i] == name[i])
        i++;
    if(!prefix[i])
    {
        while(name[i])
            i++;
#define PUTS(s) +(sizeof(s) - 1)
#define PUTN() +i
        size_t new_sz = buf->sz SQL_COMMANDS_PER_TABLE(PUTS, PUTN);
#undef PUTN
#undef PUTS
        size_t cap = buf->cap;
        if(cap < 16384)
            cap = 16384;
        if(new_sz > cap)
            cap *= 2;
        if(new_sz > cap)
            cap = new_sz;
        if(cap != buf->cap)
        {
            char* new_data = mmap(0, cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
            char* data = buf->data;
            size_t sz = buf->sz;
            for(size_t i = 0; i < sz; i++)
                new_data[i] = data[i];
            munmap(data, buf->cap);
            buf->data = new_data;
            buf->cap = cap;
        }
#define PUT(s, l)\
        for(size_t j = 0; j < l; j++)\
            buf->data[buf->sz++] = s[j];
#define PUTS(s) PUT(s, sizeof(s)-1)
#define PUTN() PUT(name, i)
        SQL_COMMANDS_PER_TABLE(PUTS, PUTN)
#undef PUTN
#undef PUTS
#undef PUT
    }
}

int(*sqlite3_open_v2)(const char*, sqlite3**, int, const char*);
int(*sqlite3_prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
int(*sqlite3_step)(sqlite3_stmt*);
const unsigned char*(*sqlite3_column_text)(sqlite3_stmt*, int);
int(*sqlite3_finalize)(sqlite3_stmt*);

//sqlite3_exec
void run_stmt(sqlite3* db, const char* cmd, struct buf* buf)
{
    while(*cmd)
    {
        sqlite3_stmt* stmt;
        const char* tail;
        if(sqlite3_prepare_v2(db, cmd, -1, &stmt, &tail) != SQLITE_OK)
            asm volatile("ud2");
        cmd = tail;
        int status;
        while((status = sqlite3_step(stmt)) == SQLITE_ROW)
            if(buf)
                log_table_name(buf, sqlite3_column_text(stmt, 0));
        if(status != SQLITE_DONE)
            asm volatile("ud2");
        sqlite3_finalize(stmt);
    }
}

void* dlopen(const char*, int);
void* dlsym(void*, const char*);

void patch_app_db(void)
{
    void* handle = dlopen("/system_ex/common_ex/lib/libSceNKWebKitRequirements.sprx", 0);
    sqlite3_open_v2 = dlsym(handle, "sqlite3_open_v2");
    sqlite3_prepare_v2 = dlsym(handle, "sqlite3_prepare_v2");
    sqlite3_step = dlsym(handle, "sqlite3_step");
    sqlite3_column_text = dlsym(handle, "sqlite3_column_text");
    sqlite3_finalize = dlsym(handle, "sqlite3_finalize");
    sqlite3* db;
    if(sqlite3_open_v2("/system_data/priv/mms/app.db", &db, SQLITE_OPEN_READWRITE, 0) != SQLITE_OK)
        asm volatile("ud2");
    struct buf buf = {};
    char* errmsg;
    run_stmt(db, "select tbl_name from sqlite_master where type = 'table';", &buf);
    char* cmd = buf.data;
    if(buf.sz == buf.cap)
    {
        cmd = mmap(0, buf.cap+16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        for(size_t i = 0; i < buf.sz; i++)
            cmd[i] = buf.data[i];
    }
    run_stmt(db, cmd, 0);
    if(buf.sz == buf.cap)
        munmap(cmd, buf.cap+16384);
    munmap(buf.data, buf.cap);
}
