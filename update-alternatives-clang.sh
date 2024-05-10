#!/usr/bin/env bash

# Colors
RESET=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BOLD=$(tput bold)

# Get available versions from /lib/llvm-*
# You can also use specific versions, e.g. VERSIONS=("14" "17" "18"), but not recommend
VERSIONS=()
for dir in /usr/lib/llvm-*; do
    if [[ -d "$dir" ]]; then
        version=$(basename "$dir" | cut -d'-' -f2)
        VERSIONS+=("$version")
    fi
done

# Loop through versions
for VERSION in "${VERSIONS[@]}"; do
    # Check if /usr/lib/llvm-${VERSION} directory exists
    if [[ -d "/usr/lib/llvm-${VERSION}" ]]; then
        # Scan paths and generate string
        alternative_string=""
        alternative_cmds=()
        for cmd in "/usr/lib/llvm-${VERSION}/bin/"*; do
            if [[ -x "$cmd" ]] && [[ "$(basename "$cmd")" != "clang" ]]; then
                base_cmd=$(basename "$cmd")
                symlink="/usr/bin/${base_cmd}-${VERSION}"
                if [[ -x "${symlink}" ]]; then
                    alternative_cmds+=($(basename ${symlink}))
                    alternative_string+="--slave /usr/bin/${base_cmd} ${base_cmd} ${symlink} "
                fi
            fi
        done

        # Remove specific alternative configuration
        update-alternatives --remove clang "/usr/bin/clang-${VERSION}" > /dev/null

        # Install alternatives
        install_command="update-alternatives \
        --quiet \
        --install /usr/bin/clang clang /usr/bin/clang-${VERSION} ${VERSION} \
        ${alternative_string}"

        # Print the concatenated string
        echo "${BOLD}${GREEN}[Adding alternative /usr/bin/clang-${VERSION} ...]${RESET}"
        echo "Master command: clang-${VERSION}"
        echo "Slave commands: ${alternative_cmds[*]}"

        eval "$install_command"

        # Check eval command's return value
        if [[ $? -eq 0 ]]; then
            echo "${BOLD}${GREEN}[Adding alternative /usr/bin/clang-${VERSION}: succeeded]${RESET}"
        else
            echo "${BOLD}${RED}[Adding alternative /usr/bin/clang-${VERSION}: failed]${RESET}"
        fi

        echo ""
    else
        # Remove specific alternative configuration if /usr/lib/llvm-${VERSION} directory does not exist
        update-alternatives --remove clang "/usr/bin/clang-${VERSION}" &> /dev/null
    fi
done

clang_path=$(update-alternatives --get-selections | grep ^clang | awk '{print $NF}')

echo "======================================================================"
echo "${GREEN}clang alternative is set to: ${clang_path}${RESET}"
echo "======================================================================"

# print helps
echo ""
echo "Info:"
num_versions=${#VERSIONS[@]}
if [[ num_versions -gt 1 ]]; then
    echo "  use '${GREEN}update-alternatives --config clang${RESET}' to change default clang alternative"
fi
echo "  use '${GREEN}update-alternatives --remove clang /usr/bin/clang-*${RESET}' to delete a clang alternative"
echo "  use '${GREEN}update-alternatives --remove-all clang${RESET}' to delete all clang alternatives"
