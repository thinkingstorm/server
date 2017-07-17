#include <argp.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#define KEYS_FOLDER "/etc/ssh"

static int auth_password(
    ssh_session session,
    const char * user,
    const char * password,
    void * userdata)
{
    printf("Authenticating user %s password %s\n", user, password);
    
    return SSH_AUTH_SUCCESS;
}

static int service_request(ssh_session session,
                           const char * service,
                           void * userdata)
{
    printf("Service request %s\n", service);
    
    return 0;
}

int main(int argc, char *argv[])
{
    ssh_bind sshbind;
    ssh_session session;
    ssh_event mainloop;
    
    struct ssh_server_callbacks_struct callbacks = {
        .userdata = NULL,
        .auth_password_function = auth_password,
        .service_request_function = service_request
    };
    
    ssh_init();
    sshbind = ssh_bind_new();
    session = ssh_new();
    
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "/etc/ssh/ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key");
    
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }
    
    if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        printf("Error accepting a connection: %s\n", ssh_get_error(sshbind));
    }
    
    ssh_callbacks_init(&callbacks);
    ssh_set_server_callbacks(session, &callbacks);
    
    if (ssh_handle_key_exchange(session) != SSH_OK) {
        printf("Error handle key exchange: %s\n", ssh_get_error(session));
        return 1;
    }
    
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);
    
    ssh_event_dopoll(mainloop, -1);
    
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
