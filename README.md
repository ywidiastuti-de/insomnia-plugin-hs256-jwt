# insomnia-plugin-hs256-jwt

An [Insomnia](https://insomnia.rest) template tag that generates an **HS256 JWT**, fresh on every request. The signing secret is read directly from your local fault credentials, the same files used by [insomnia-plugin-fault-variables](https://insomnia.rest/plugins/insomnia-plugin-fault-variables), so it never has to be stored in your Insomnia workspace.

## Install

In Insomnia, open **Preferences → Plugins**, enter `insomnia-plugin-hs256-jwt` and click **Install Plugin**.

## Usage

In any request field (for example an `Authorization` header), press `Ctrl+Space` (`Cmd+Space` on macOS), choose **HS256 JWT**, and fill in the options:

| Option | Description |
| --- | --- |
| Fault Project | Fault project ID, e.g. `com.example.app:api`. |
| Fault Filepath | Path within the fault project, e.g. `local/.properties`. |
| Secret Property | Key of the signing secret in that file, e.g. `jwt.secret`. |
| Tenant ID | Value for the `tenant_id` claim. Leave empty to leave the claim out. |
| Expiry (seconds) | Lifetime of the token. Default `3600`. |
| Secret Encoding | `UTF-8` uses the secret as-is. `Base64` decodes it first, which is common for Spring Boot services. |

Every text option also accepts an environment variable, e.g. `{{ _.project }}` or `{{ _['property-jwt-secret'] }}`.

Example header:

```
Authorization: Bearer <HS256 JWT tag>
```

### Where the secret is read from

```
~/.fault/<Fault Project>/<Fault Filepath>
```

On Windows, colons are removed from the project ID (`com.example.app:api` → `com.example.appapi`), matching insomnia-plugin-fault-variables. The file is a standard `.properties` file:

```properties
jwt.secret=change-me
```

### Generated token

- Header: `{"alg": "HS256", "typ": "JWT"}`
- Payload: `tenant_id` (if set), `iat` and `exp`.
- `iat` is backdated by 60 seconds so a server whose clock runs slightly behind does not reject the token as issued in the future.

## Author

Yuni Widiastuti — [yuni.widiastuti@gmail.com](mailto:yuni.widiastuti@gmail.com)

## License

MIT
