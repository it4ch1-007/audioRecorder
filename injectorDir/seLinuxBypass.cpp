#include "seLinuxBypass.h"
#include <fcntl.h>
#include <android/log.h>
#include "sepol/policydb/services.h"
#include "sepol/policydb/policydb.h"
#include "selinux.h"

#define SELINUX_ERROR selinux_error_quark()

#define LOG_TAG "seLinuxBypass.cpp"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

typedef struct _SELinuxRules SELinuxRules;
typedef enum _SELinuxErrorEnum SELinuxErrorEnum;

struct _SELinuxRules
{
    const char *sources[4];
    const char *target;
    const char *klass;
    const char *perms[16];
};

enum _SELinuxErrorEnum
{
    SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED,
    SELINUX_ERROR_TYPE_NOT_FOUND,
    SELINUX_ERROR_CLASS_NOT_FOUND,
    SELINUX_ERROR_PERMS_NOT_FOUND,
};

typedef struct Error
{
    GQuark domain;
    gint code;
    gchar *message;
} Error;

static bool load_policy(const char *filename, policydb_t *policydb, char **data, Error **error);
static bool save_policy(const char *filename, policydb_t *policydb, Error **error);
static type_datum_t ensure_type(policydb_t *policydb, const char *type, uint num_attrs, ...);
static void add_type_to_class_constraints_ref_attr(policydb_t *policydb, uint32_t *type_id, uint32_t attr_id);
static void ensure_permissive(policydb_t *policydb, const char *type, Error *error);
static avtab_datum_t ensure_rule(policydb_t *policydb, const char *source, const char *target, const char *klass, const char *perms, Error **error);

static bool set_file_contents(const char *filename, const char *contents, ssize_t length, Error **error);

static const SELinuxRules seLinuxRules[] =
    {
        // We will use domain to be able to hook every process inside the device.
        // TODO: We will require to label as `injector_file` if we need custom rules for the files particularly
        {{"domain", NULL}, "domain", "process", {"execmem", NULL}},
        {{"domain", NULL}, "$self", "dir", {"search", NULL}},
        {{"domain", NULL}, "$self", "file", {"open", "read", "write", "getattr", "execute", "?map", NULL}},
        {{"domain", NULL}, "shell_data_file", "dir", {"search", NULL}},
        {{"domain", NULL}, "zygote_exec", "file", {"execute", NULL}},
        {{"domain", NULL}, "$self", "process", {"sigchild", NULL}},
        {{"domain", NULL}, "$self", "fd", {"use", NULL}},
        {{"domain", NULL}, "$self", "unix_stream_socket", {"connectto", "read", "write", "getattr", "getopt", NULL}},
        {{"domain", NULL}, "$self", "tcp_socket", {"read", "write", "getattr", "getopt", NULL}},
        {{"zygote", NULL}, "zygote", "capability", {"sys_ptrace", NULL}},
        {{"?app_zygote", NULL}, "zygote_exec", "file", {"read", NULL}},
        {{"system_server", NULL}, "?apex_art_data_file", "file", {"execute", NULL}},
};

G_DEFINE_QUARK(selinux - error - quark, selinux_error)

void selinux_bypass_patch()
{
    const char *system_policy = "/sys/fs/selinux/policy";
    policydb_t policydb;
    char *db_data;
    sidtab_t *sidtab;
    GError *error = NULL;
    int res G_GNUC_UNUSED;
    uint rule_index;

    sepol_set_policydb(&policydb);
    sepol_set_sidtab(sidtab);

    if (!g_file_test(system_policy, G_FILE_TEST_EXISTS))
    {
        g_warning("SELinux policy file does not exist: %s", system_policy);
        return;
    }

    // Loading sepolicy
    if (!load_policy(system_policy, &policydb, &db_data, &error))
    {
        g_warning("Failed to load SELinux policy: %s\n", error->message);
        g_clear_error(&error);
        return;
    }

    res = policydb_load_isids(&policydb, sidtab);
    if (res != 0)
    {
        g_warning("Failed to load SELinux policy isids");
        g_free(db_data);
        return;
    }

    if (ensure_type(&policydb, "injector", 2, "file_type", "mlstrustedobject", &error) == NULL)
    {
        g_printerr("Unable to add SELinux type: %s\n", error->message);
        g_clear_error(&error);
        goto beach;
    }

    for (rule_index = 0; rule_index != G_N_ELEMENTS(seLinuxRules); rule_index++)
    {
        const SELinuxRules *rule = &seLinuxRules[rule_index];
        const char *target = rule->target;
        const char *const *source_cursor;
        const char *const *perm_entry;

        if (target[0] == '?')
        {
            target++;

            if (hashtab_search(policydb.p_types.table, (char *)target) == NULL)
                continue;
        }

        for (source_cursor = rule->sources; *source_cursor != NULL; source_cursor++)
        {
            const char *source = *source_cursor;

            if (source[0] == '?')
            {
                source++;

                if (hashtab_search(policydb.p_types.table, (char *)source) == NULL)
                    continue;
            }

            for (perm_entry = rule->perms; *perm_entry != NULL; perm_entry++)
            {
                const char *perm = *perm_entry;
                bool is_important = TRUE;

                if (perm[0] == '?')
                {
                    is_important = FALSE;
                    perm++;
                }

                if (ensure_rule(&policydb, source, target, rule->klass, perm, &error) == NULL)
                {
                    if (!g_error_matches(error, SELINUX_ERROR, SELINUX_ERROR_PERMS_NOT_FOUND) || is_important)
                        g_printerr("Unable to add SELinux rule: %s\n", error->message);
                    g_clear_error(&error);
                }
            }
        }
    }

    if (!save_policy("/sys/fs/selinux/load", &policydb, &error))
    {
        bool success = FALSE, probably_in_emulator;

        probably_in_emulator = security_getenforce() == 1 && security_setenforce(0) == 0;
        if (probably_in_emulator)
        {
            g_clear_error(&error);

            success = ensure_permissive(&policydb, "shell", &error);
            if (success)
                success = save_policy("/sys/fs/selinux/load", &policydb, &error);

            security_setenforce(1);
        }

        if (!success)
        {
            g_printerr("Unable to save SELinux policy to the kernel: %s\n", error->message);
            g_clear_error(&error);
        }
    }

beach:
    policydb_destroy(&policydb);
    g_free(db_data);
}

static bool load_policy(const char *filename, policydb_t *policydb, char **data, GError **error)
{
    policy_file_t file;
    int res;

    policy_file_init(&file);
    file.type = PF_USE_MEMORY;
    if (!g_file_get_contents(filename, &file.data, &file.len, error))
        return FALSE;

    *data = file.data;
    policydb_init(policydb);
    res = policydb_read(policydb, &file, FALSE);
    if (res != 0)
    {
        g_set_error(error, SELINUX_ERROR, SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED,
                    "Failed to load SELinux policy from file %s", filename);
        policydb_destroy(policydb);
        g_free(*data);
        return FALSE;
    }

    return TRUE;
}

static bool save_policy(const char *filename, policydb_t *policydb, GError **error)
{
    void *data;
    size_t size;
    int res G_GNUC_UNUSED;

    res = policydb_to_image(NULL, policydb, &data, &size);
    if (res != 0)
    {
        LOGD("Failed to convert SELinux policydb to image");
        return FALSE;
    }

    return set_file_contents(filename, (const char *)data, size, error);
}

static type_datum_t *ensure_type(policydb_t *policydb, const char *type, uint num_attrs, ...)
{
    type_datum_t *type_datum;
    uint32_t type_id;
    va_list vl;
    uint i;
    GError *pending_error, **error;

    type = hashtab_search(policydb->p_types.table, (char *)type);
    if (type == NULL)
    {
        uint32_t i, n;
        char *name;
        type_id = ++policydb->p_types.nprim;
        name = strdup(type);

        type = malloc(sizeof(type_datum_t));

        type_datum_init(type);
        type->s.value = type_id;
        type->primary = TRUE;
        type->flavor = TYPE_TYPE;

        hashtab_insert(policydb->p_types.table, name, type);
        policydb_index_others(NULL, policydb, FALSE);

        i = type_id - 1;
        n = policydb->p_types.nprim;
        policydb->type_attr_map = realloc(policydb->type_attr_map, n * sizeof(ebitmap_t));
        policydb->type_attr_map = realloc(policydb->attr_type_map, n * sizeof(ebitmap_t));
        ebitmap_init(&policydb->type_attr_map[i]);
        ebitmap_init(&policydb->attr_type_map[i]);

        ebitmap_set_bit(&policydb->type_attr_map[i], i, 1);
    }
    else
    {
        type_id = type->s.value;
    }

    va_start(vl, num_attrs);

    pending_error = NULL;
    for (i = 0; i != num_attrs; i++)
    {
        const char *attr_name;
        type_datum_t *attr_type;

        attr_name = va_arg(vl, const char *);
        attr_type = hashtab_search(policydb->p_types.table, (char *)attr_name);
        if (attr_type != NULL)
        {
            uint32_t attr_id = attr_type->s.value;
            ebitmap_set_bit(&attr_type->types, type_id - 1, 1);
            ebitmap_set_bit(&policydb->type_attr_map[type_id - 1], attr_id - 1, 1);
            ebitmap_set_bit(&policydb->attr_type_map[attr_id - 1], type_id - 1, 1);

            add_type_to_class_constraints_ref_attr(policydb, type_id, attr_id);
        }
        else if (pending_error == NULL)
        {
            g_set_error(&pending_error, SELINUX_ERROR, SELINUX_ERROR_TYPE_NOT_FOUND,
                        "Attribute type '%s' not found while ensuring type '%s'", attr_name, type);
        }
    }

    error = va_arg(vl, Error **);
    if (pending_error != NULL)
        g_propagate_error(error, pending_error);

    va_end(vl);

    return (pending_error == NULL) ? type : NULL;
}

static bool set_file_contents(const char *filename, const char *contents, ssize_t length, GError **error)
{
    // Writing contents to the file
    int fd, res;
    size_t offset, size;

    fd = open(filename, O_RDWR);
    if (fd == -1)
        goto error;
    offset = 0;
    size = (length == -1) ? strlen(contents) : length;
    while (offset != size)
    {
        res = write(fd, contents + offset, size - offset);
        if (res == -1)
            goto error;
        offset += res;
    }

    close(fd);

    return TRUE;

error:
{
    int err;
    err = errno;
    g_set_error(error, SELINUX_ERROR, err,
                "Failed to open file '%s' for writing: %s", filename, strerror(err));

    if (fd != -1)
        close(fd);
    return FALSE;
}
}

static bool ensure_permissive(policydb_t *policydb, const char *type, G_ASCII_LOWER *error)
{
    // If our custom policies fail then we can set the selinux bit as 1 for our process and then we can bypass all the selinux policies for the process
    type_datum_t *type;
    int res G_GNUC_UNUSED;

    type = hashtab_search(policydb->p_types.table, (char *)type);
    if (type == NULL)
    {
        g_set_error(&error, SELINUX_ERROR, SELINUX_ERROR_TYPE_NOT_FOUND,
                    "Type '%s' not found while ensuring permissive", type);
        return FALSE;
    }

    res = ebitmap_set_bit(&policydb->permissive_map, type->s.value, 1);
    if (res != 0)
    {
        g_set_error(&error, SELINUX_ERROR, SELINUX_ERROR_TYPE_NOT_FOUND,
                    "Failed to set permissive for type '%s'", type);
        return FALSE;
    }

    return TRUE;
}

static avtab_datum_t ensure_rule(policydb_t *policydb, const char *source, const char *target, const char *klass, const char *perms, GError **error)
{
    type_datum_t *source, *target;
    gchar *self_type = NULL;
    class_datum_t *klass;
    perm_datum_t *perm;
    avtab_key_t key;
    avtab_datum_t *av;
    uint32_t perm_bit;

    source = hashtab_search(db->p_types.table, (char *)s);
    if (source == NULL)
    {
        g_set_error(error, SELINUX_ERROR, SELINUX_ERROR_TYPE_NOT_FOUND, "source type “%s” does not exist", s);
        return NULL;
    }

    if (strcmp(t, "$self") == 0)
    {
        char *self_context;
        gchar **tokens;

        getcon(&self_context);

        tokens = g_strsplit(self_context, ":", 4);

        self_type = g_strdup(tokens[2]);
        t = self_type;

        g_strfreev(tokens);

        freecon(self_context);
    }

    target = hashtab_search(db->p_types.table, (char *)t);

    g_free(self_type);

    if (target == NULL)
    {
        g_set_error(error, SELINUX_ERROR, SELINUX_ERROR_TYPE_NOT_FOUND, "target type “%s” does not exist", t);
        return NULL;
    }

    klass = hashtab_search(db->p_classes.table, (char *)c);
    if (klass == NULL)
    {
        g_set_error(error, SELINUX_ERROR, SELINUX_ERROR_CLASS_NOT_FOUND, "class “%s” does not exist", c);
        return NULL;
    }

    perm = hashtab_search(klass->permissions.table, (char *)p);
    if (perm == NULL && klass->comdatum != NULL)
        perm = hashtab_search(klass->comdatum->permissions.table, (char *)p);
    if (perm == NULL)
    {
        g_set_error(error, SELINUX_ERROR, SELINUX_ERROR_PERMS_NOT_FOUND, "perm “%s” does not exist on the “%s” class", p, c);
        return NULL;
    }
    perm_bit = 1U << (perm->s.value - 1);

    key.source_type = source->s.value;
    key.target_type = target->s.value;
    key.target_class = klass->s.value;
    key.specified = AVTAB_ALLOWED;

    av = avtab_search(&db->te_avtab, &key);
    if (av == NULL)
    {
        int res G_GNUC_UNUSED;

        av = malloc(sizeof(avtab_datum_t));
        av->data = perm_bit;
        av->xperms = NULL;

        res = avtab_insert(&db->te_avtab, &key, av);
        g_assert(res == 0);
    }

    av->data |= perm_bit;

    return av;
}

static void add_type_to_class_constraints_referencing_attribute(policydb_t *policydb, uint32_t type_id, uint32_t attr_id)
{
    uint32_t class_index;

    for (class_index = 0; class_index != policydb->p_classes.nprim; class_index++)
    {
        class_datum_t *klass = policydb->class_val_to_struct[class_index];
        constraint_node_t *node;

        for (node = klass->constraints; node != NULL; node = node->next)
        {
            constraint_expr_t *expr;

            for (expr = node->expr; expr != NULL; expr = expr->next)
            {
                ebitmap_node_t *tnode;
                guint i;

                ebitmap_for_each_bit(&expr->type_names->types, tnode, i)
                {
                    if (ebitmap_node_get_bit(tnode, i) && i == attr_id - 1)
                        ebitmap_set_bit(&expr->names, type_id - 1, 1);
                }
            }
        }
    }
}