/*
 * 漏洞测试样例 - 包含各种 C/C++ 安全问题
 */

// 1. Buffer Overflow - CWE-120
void vulnerable_strcpy(char *dest, const char *src) {
    strcpy(dest, src);  // 没有长度检查
}

void vulnerable_sprintf() {
    char buffer[50];
    sprintf(buffer, "User input: %s", user_input);  // 潜在的缓冲区溢出
}

// 2. Format String - CWE-134
void vulnerable_printf(char *input) {
    printf(input);  // 直接使用用户输入作为格式字符串
}

void vulnerable_fprintf() {
    fprintf(stdout, user_input);  // 未控制的格式字符串
}

// 3. Use After Free - CWE-416
void vulnerable_use_after_free() {
    char *buffer = malloc(100);
    free(buffer);
    strcpy(buffer, "after free");  // 使用已释放的内存
}

// 4. Null Pointer Dereference - CWE-476
void vulnerable_null_deref(char *ptr) {
    if (ptr == NULL) {
        return;
    }
    int x = strlen(ptr);  // 这里其实有检查，但下面是危险的
    if (!ptr) {
        printf("%s", ptr);  // 条件判断多余，可能导致问题
    }
}

// 5. Integer Overflow - CWE-190
void vulnerable_malloc() {
    size_t size = user_size + 1000;
    char *buffer = malloc(size);  // user_size 可能导致整数溢出
}

// 6. Command Injection - CWE-78
void vulnerable_system() {
    char cmd[256];
    sprintf(cmd, "ls -la %s", user_path);  // 危险的用户输入拼接到命令
    system(cmd);
}

// 7. SQL Injection - CWE-89
void vulnerable_sql() {
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", username);
    sqlite3_exec(db, query, NULL, NULL, NULL);  // SQL 注入风险
}

// 8. 安全的代码示例（不应被标记）
void safe_strcpy(char *dest, const char *src, size_t size) {
    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';
}

void safe_printf(const char *format, ...) {
    // 正确的 printf 使用方式
}
