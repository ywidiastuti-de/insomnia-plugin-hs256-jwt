# insomnia-plugin-hs256-jwt

An [Insomnia](https://insomnia.rest) template tag that generates an **HS256 JWT** signed with a shared secret, fresh on every request.

## Install

In Insomnia, open **Preferences → Plugins**, enter `insomnia-plugin-hs256-jwt` and click **Install Plugin**.

## Usage

In any request field (for example an `Authorization` header), press `Ctrl+Space` (`Cmd+Space` on macOS), choose **HS256 JWT**, and fill in the options:

| Option | Description |
| --- | --- |
| Secret Source | **Value**: type the secret or reference an environment variable such as `{{ _.jwtSecret }}`. **Properties file**: read it from a `.properties` file on disk. |
| Secret | The signing secret (Value source only). |
| Properties File | Path to the `.properties` file; `~` expands to your home directory (Properties file source only). |
| Secret Property | Key of the secret in that file, e.g. `jwt.secret` (Properties file source only). |
| Secret Encoding | `UTF-8` uses the secret as-is. `Base64` decodes it first, which is common for Spring Boot services. |
| Expiry (seconds) | Lifetime of the token. Default `3600`. |
| Extra Claims (JSON) | A JSON object merged into the payload, e.g. `{"sub": "user-1", "tenant_id": "acme"}`. |

Example header:

```
Authorization: Bearer <HS256 JWT tag>
```

### Generated token

- Header: `{"alg": "HS256", "typ": "JWT"}`
- Payload: your extra claims plus `iat` and `exp`.
- `iat` is backdated by 60 seconds so a server whose clock runs slightly behind does not reject the token as issued in the future.

### Keeping secrets out of your workspace

Using the **Properties file** source keeps the secret out of your Insomnia workspace and exports. Example file:

```properties
# ~/secrets/app.properties
jwt.secret=change-me
```

## Author

Yuni Widiastuti — [yuni.widiastuti@gmail.com](mailto:yuni.widiastuti@gmail.com)

## License

MIT
