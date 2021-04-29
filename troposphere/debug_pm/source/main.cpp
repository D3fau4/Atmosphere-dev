#include <string.h>
#include <stdio.h>
#include <switch.h>
#include <string>

struct RegistrationRecord
{
    uint64_t service_name;
    uint64_t owner_pid;
    uint64_t max_sessions;
    uint64_t mitm_pid;
    uint64_t mitm_waiting_ack_pid;
    bool is_light;
    bool mitm_waiting_ack;
};

static Result smAtmosphereCmdHas(bool *out, SmServiceName name, u32 cmd_id)
{
    u8 tmp;
    Result rc = tipcDispatchInOut(smGetServiceSessionTipc(), cmd_id, name, tmp);
    if (R_SUCCEEDED(rc) && out)
        *out = tmp & 1;
    return rc;
}

static Result smAtmosphereCmdGetRecord(RegistrationRecord *out, u64 index, u32 cmd_id)
{
    RegistrationRecord tmp;
    Result rc = tipcDispatchInOut(smGetServiceSessionTipc(), cmd_id, index, tmp);
    *out = tmp;
    return rc;
}

static Result smAtmosphereCmdGetCount(u64 *out, u32 cmd_id)
{
    u64 tmp;
    Result rc = tipcDispatchOut(smGetServiceSessionTipc(), cmd_id, tmp);
    *out = tmp;
    return rc;
}

Result smAtmosphereHasService(bool *out, SmServiceName name)
{
    return smAtmosphereCmdHas(out, name, 65100);
}

Result smGetRecord(RegistrationRecord *out, u64 index)
{
    return smAtmosphereCmdGetRecord(out, index, 65103);
}

Result smGetCount(u64 *out)
{
    return smAtmosphereCmdGetCount(out, 65104);
}

int main(int argc, char **argv)
{
    consoleInit(NULL);

    // Configure our supported input layout: a single player with standard controller styles
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);

    // Initialize the default gamepad (which reads handheld mode inputs as well as the first connected controller)
    PadState pad;
    padInitializeDefault(&pad);

    uint64_t offset = 0;
    uint64_t count;
    uint64_t record_size = 0;

    Result rc = smInitialize();
    if (R_FAILED(rc))
        printf("[ERROR] smInitialize() 0x%x.\n", rc);

    rc = smGetCount(&count);
    if (R_FAILED(rc))
        printf("[ERROR] smAtmosphereGetRecord() 0x%x.\n", rc);

    FILE *f;
    f = fopen("SM.log", "wb");

    fprintf(f, "Name       | Owner | Max Sessions | Is Light | MITM Pid | MITM Waiting Ack PID | MITM Waiting Ack\n");
    for (int i = 0; i < count; i++)
    {
        RegistrationRecord record;
        rc = smGetRecord(&record, i);
        if (R_FAILED(rc))
            printf("[ERROR] smGetRecord() 0x%x.\n", rc);
        char name[9] = {0};
        memcpy(name, &record.service_name, sizeof(record.service_name));
        char path[255];
        char *bool1;
        char *bool2;
        if (record.mitm_waiting_ack == true)
            bool1 = "true";
        else 
            bool1 = "false";
        if (record.is_light == true)
            bool2 = "true";
        else 
            bool2 = "false";
        fprintf(f, "'%s' | 0x% 3l | %12l | %ln | 0x% 6l | 0x% 18l | %ln\n", name, &record.owner_pid, &record.max_sessions, bool2, &record.mitm_pid, &record.mitm_waiting_ack_pid, bool1);
    }
    fclose(f);

    printf("Log writed!");

    // Main loop
    while (appletMainLoop())
    {
        // Scan the gamepad. This should be done once for each frame
        padUpdate(&pad);

        // Your code goes here

        // padGetButtonsDown returns the set of buttons that have been newly pressed in this frame compared to the previous one
        u64 kDown = padGetButtonsDown(&pad);

        if (kDown & HidNpadButton_Plus)
            break; // break in order to return to hbmenu

        consoleUpdate(NULL);
    }

    smExit();
    consoleExit(NULL);
    return 0;
}