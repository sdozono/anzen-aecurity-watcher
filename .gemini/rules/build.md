# Build and Release Guidelines

- For any build, compile check, or package step in this workspace, always target the `Release` configuration.
- The default project configuration in `AnzenSecurityWatcher.csproj` is set to `Release`.
- When running `dotnet build`, build outputs are placed in `bin\Release\net8.0-windows\`.
- If an output file is locked because the application is actively running, inform the user to close the app before updating the binaries.
