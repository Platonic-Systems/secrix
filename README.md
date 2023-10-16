# Secrix

Secrex is based on ideas in [agenix](https://github.com/ryantm/agenix), however is written from the ground up.

Secrix allows you to bind secrets to systemd services to ensure that their lifetime is only as long as the service itself. As well, it allows for system secrets, which are by default bound to the lifetime of the system. All secrets are stored in virtual memory and do not end up on disk.

Creating a service secret is as easy as `secrix.services.<systemd-service>.secrets.<name>.encrypted.file`. Its final location will end up in `secrix.services.<systemd-service>.secrets.<name>.decrypted.path`. System secrets are defined as `secrix.system.secrets`, with the same pattern as service secrets, minus the service.

For encryption/decryption usage, see `nix run .#secrix -- --help`.

## Adding Secrix

```nix
inputs.secrix.url = "github:Platonic-Systems/secrix";
```

## Getting Started

In your `flake.nix`, simply define an `app` as such:

```nix
{
    apps.x86_64-linux.secrix = inputs.secrix.secrix self;
}
```

This in and of itself is enough to start using Secrix. Ideally, for ease of use, you should define some options that
will make your life easier when using Secrix. Defining `secrix.defaultEncryptKeys` (or
`encryptKeys` for any given secret) as an attribute set as such:

```nix
secrix.defaultEncryptKeys = {
    my-user = [ "my-key" ];
}
```

will allow you to use `-u my-user` when encrypting a secret. Similarly, defining `secrix.hostPubKey` for some
`nixosConfigurations` will allow you to use `-s my-host` (assuming `outputs.nixosConfigurations.my-host`).

## Defining Secrets

### Binding a Secret to a Service

Service secrets are bound specifically to systemd services. For example, Minio:

```nix
{
    secrix.services.minio.secrets.minio-rootCreds.encrypted.file = ./secrets/minio-rootCreds;
    minio = {
        ...
        rootCredentialsFile = config.secrix.services.minio.secrets.minio-rootCreds.decrypted.path;
    };
}
```

This will ensure that the secret itself is owned and accessible by the minio user and will only be extant while minio is up.

### System Secrets

System secrets are not bound to anything except the system's lifetime via their own service. For example:

```nix
{
    secrix.system.secrets.my-secret.encrypted.file = ./secrets/my-secret;
}
```

`secrix.system.secrets.my-secret.decrypted.path` can be used to get its final path on the system when decrypted.

## Options

### `secrix.ageBin`

The age bin to use for encryption and decryption.

* Type: String
* Default: `"${pkgs.age}/bin/age"`

### `secrix.hostIdentityFile`

The private key of the host that will be decrypting the secret.

* Type: String
* Default: `"/etc/ssh/ssh_host_ed25519_key"`

### `secrix.defaultEncryptKeys`

The default encryption keys for all secrets. This will be overriden for any given secret if `encryptKeys` is specified for that secret.

* Type: AttrSet of Lists of Strings
* Default: `{}`

### `secrix.hostPubKey`

The public key for the host that the secrets will exist on.

* Type: Null or String
* Default: `null`

### `secrix.system.secretsDir.name`

The name of the directory for system secrets. It will end up as `/run/<name>`.

* Type: String
* Default: `system-keys`

### `secrix.system.secretsDir.permissions`

Permissions for the directory containing system secrets.

* Type: String
* Default: `111`

### `secrix.system.secretsDir.user`

The user that owns the directory for system secrets.

* Type: String
* Default: `"0"`

### `secrix.system.secretsDir.group`

The group that owns the directory for system secrets.

* Type: String
* Default: `"0"`

### `secrix.system.secretsServiceName`

The name of the service that manages system secrets.

* Type: String
* Default: `"system-keys"`

### `secrix.system.secrets`

An attribute set of secrets that will be decrypted on the system. System secrets will be decrypted at system start and will exist decrypted for the uptime of the system but will not remain on disk if the system is shut down sanely.

* Type: AttrSet of Submodules
* Default: `{}`

### `secrix.system.secrets.<name>.name`

The name of the secret. This defaults to the attribute name. This is simply a referential token to the secret, however if no name is set for the decrypted file, this will be used.

* Type: String
* Default: `<name>`

### `secrix.system.secrets.<name>.encryptKeys`

Public keys with which to encrypt the secret.

* Type: AttrSet of Lists of Strings
* Default: `secrix.defaultEncryptKeys`

### `secrix.system.secrets.<name>.encrypted.file`

Local location of the secret.

* Type: Path

### `secrix.system.secrets.<name>.decrypted.name`

The name of the decrypted file on disk. This defaults to the secret name.

* Type: String
* Default: `secrix.system.secrets.<name>.name`

### `secrix.system.secrets.<name>.decrypted.mode`

Permissions of the secret when decrypted.

* Type: String
* Default: `"0400"`

### `secrix.system.secrets.<name>.decrypted.user`

Secret user.

* Type: String
* Default: `"0"`

### `secrix.system.secrets.<name>.decrypted.group`

Secret group.

* Type: String
* Default: `"0"`

### `secrix.system.secrets.<name>.decrypted.path`

The path to the secret when decrypted on disk. This is automatically set by secrix and is available only for reference.

* Type: String
* Default: `"/run/${secrix.system.secretsDir.name}/${secrix.system.secrets.<name>.name}"`
* Read Only

### `secrix.system.secrets.<name>.decrypted.builder`

A builder script (if needed) to perform additional actions on the secret before it ends up in its final location.

If this is a function that yields a string, it will be passed a single argument which is the final location of the built file.

If this is a string, a special bash variable $inFile can be used to reference the secret as it is, however there will be no reference available to its final destination as that will be up to the builder. Use a string only if you know what you're doing.

* Type: Null or Either Lines or `String -> Lines`
* Default: `null`

### `secrix.services`

An attribute set of systemd service names to which to bind secrets. All secrets bound to a service will exist only for the lifetime of the service.

* Type: AttrSet of Submodules
* Default: `{}`

### `secrix.services.<service>.secretsDirName`

The directory name for the service secrets.

* Type: String
* Default: `"<name>-keys"`

### `secrix.services.<service>.systemdService`

The name fo the systemd service that the secrets contained within will be bound to. This defaults to the attribute name.

* Type: String
* Default: `<service>`

### `secrix.services.<service>.additionalRuntimeDirNames`

In the case that the systemd service these secrets will be bound to has a RuntimeDirectory specified as a string, secrix will be unable to add an additional RuntimeDirectory, so add that here.

* Type: List of Strings
* Default: `[]`

### `secrix.services.<service>.forceRuntimeDirs`

Set this to true of the service these secrets will be bound to has a RuntimeDirectory already specified as a string.

* Type: Boolean
* Default: `false`

### `secrix.services.<service>.secretsServiceName`

The name of the service that will decrypt the keys.

* Type: String
* Default: `<name>-keys`

### `secrix.services.<service>.secrets`

An attribute set of secrets that will be decrypted on the system. Service secrets will be decrypted at the start of and will exist for the lifetime of the service they are bound to.

* Type: AttrSet of Submodules

### `secrix.services.<service>.secrets.<name>.name`

The name of the secret. This defaults to the attribute name. This is simply a referential token to the secret, however if no name is set for the decrypted file, this will be used.

* Type: String
* Default: `<name>`

### `secrix.services.<service>.secrets.<name>.encryptKeys`

Public keys with which to encrypt the secret.

* Type: AttrSet of Lists of Strings
* Default: `secrix.defaultEncryptKeys`

### `secrix.services.<service>.secrets.<name>.encrypted.file`

Local location of the secret.

* Type: Path

### `secrix.services.<service>.secrets.<name>.decrypted.name`

The name of the decrypted file on disk. This defaults to the secret name.

* Type: String
* Default: `secrix.services.<service>.secrets.<name>.name`

### `secrix.services.<service>.secrets.<name>.decrypted.mode`

Permissions of the secret when decrypted.

* Type: String
* Default: `0400`

### `secrix.services.<service>.secrets.<name>.decrypted.user`

Secret user.

* Type: String
* Default: `systemd.services.<service>.serviceConfig.User or "0"`

### `secrix.services.<service>.secrets.<name>.decrypted.group`

Secret group.

* Type: String
* Default: `systemd.services.<service>.serviceConfig.Group or "0"`

### `secrix.services.<service>.secrets.<name>.decrypted.path`

The path to the secret when decrypted on disk. This is automatically set by secrix and is available only for reference.

* Type: String
* Default: `"/run/${secrix.services.<service>.secretsDirName}/${secrix.services.<service>.secrets.<name>.name}"`
* Read Only

### `secrix.services.<service>.secrets.<name>.decrypted.builder`

A builder script (if needed) to perform additional actions on the secret before it ends up in its final location.

If this is a function that yields a string, it will be passed a single argument which is the final location of the built file.

If this is a string, a special bash variable $inFile can be used to reference the secret as it is, however there will be no reference available to its final destination as that will be up to the builder. Use a string only if you know what you're doing.

* Type: Null or Either Lines or `String -> Lines`
* Default: `null`
