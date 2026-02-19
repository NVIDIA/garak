import tomllib


def main(argv=None) -> None:
    prev_version = None
    version = None
    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)
        prev_version = data["project"]["version"]
        version_parts = prev_version.split(".")
        if len(version_parts) == 4:
            version = ".".join(version_parts[:3])
        else:
            version_parts[-1] = str(int(version_parts[-1]) + 1)
            version_parts.append("pre1")
            version = ".".join(version_parts)
    print(version, end="")
    if version:
        files = ("pyproject.toml", "garak/__init__.py")
        for file in files:
            with open(file, "r") as f:
                content = f.read()
            with open(file, "w") as f:
                new_content = content.replace(prev_version, version, 1)
                f.write(new_content)


if __name__ == "__main__":
    main()
