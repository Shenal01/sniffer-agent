# Guide: Pushing Sniffer Agent to GitHub

This guide will walk you through the steps to initialize a Git repository for this project and push it to GitHub.

## Prerequisites

1. **Git Installed**: Ensure you have Git installed on your machine. You can check by running `git --version` in your terminal.
2. **GitHub Account**: You need a GitHub account.
3. **New Repository**: Create a new repository on GitHub (e.g., named `sniffer-agent`). **Do not** initialize it with a README, license, or `.gitignore` since we already have the files locally.

## Step-by-Step Instructions

### 1. Initialize Git Locally

Open your terminal in the project directory (`e:\Year 4 Semester 2\FYP\Exfiltrap-prototype-2\sniffer_agent`) and run:

```bash
git init
```

### 2. Add All Files

Add your project files to the staging area. The `.gitignore` file I created will automatically exclude unnecessary build files and sensitive data.

```bash
git add .
```

### 3. Create First Commit

Commit the files with a meaningful message:

```bash
git commit -m "Initial commit of Unified Sniffer Agent project"
```

### 4. Link to GitHub

Run this command to link your local project to your GitHub repository:

```bash
git remote add origin https://github.com/sayu-gtss/sniffer-agent.git
```
*(Ensure you have created a repository named `sniffer-agent` on GitHub first)*

### 5. Rename Main Branch (Recommended)

GitHub uses `main` as the default branch name. Run this to ensure your local branch matches:

```bash
git branch -M main
```

### 6. Push to GitHub

Finally, push your code to GitHub:

```bash
git push -u origin main
```

> [!NOTE]
> If it's your first time pushing from this machine, you may be prompted to log in to GitHub via a browser or using a Personal Access Token (PAT).

---

## Why Push to GitHub? (Local vs. Remote)

You have already **committed** your code. This means your work is saved in a local database on your computer (`E:` drive).

### What is "Remaining" if you don't push?
1. **Cloud Backup**: If your computer's hard drive fails or you lose access to it, your code is lost forever. GitHub acts as a secure backup.
2. **Access from Anywhere**: You can't see your code on `github.com` yet. Pushing makes it visible in the browser.
3. **Collaboration**: If you want to show this to your professor or teammates, you need it on GitHub so they can download it.

### Commands to finish:
- `git remote add origin https://github.com/sayu-gtss/sniffer-agent.git`
- `git push -u origin main`

---

## What files are NOT uploaded? (The `.gitignore` file)

I created a `.gitignore` file in your project. This file tells Git to skip certain files so your repository stays clean and secure.

### Excluded Files List:
1.  **Build Folders (`unified_sniffer_agent/build/`, `bin/`)**: These contain temporary files created when you compile the C++ code. You don't need them on GitHub because you can recreate them by building the project again.
2.  **Executables (`*.exe`, `*.obj`)**: The final program files. GitHub should host your **source code**, not the compiled binaries.
3.  **Large Zip Files (`exfiltrap_v2.0-sniffer_agent.zip`)**: Large archives make the repository slow and are redundant if the files are already in the repo.
4.  **Sensitive Data (`service-account.json`)**: This file contains your Google Cloud credentials. **NEVER** upload this to a public GitHub repository, or others could access your Google Sheets.
5.  **External Dependencies (`vcpkg/`, `node_modules/`)**: These are libraries downloaded from elsewhere. It's better to let people download them using the setup scripts rather than bloating your repo.
6.  **IDE Settings (`.vscode/`, `.idea/`)**: These are your personal VS Code or editor settings, which might not be the same for everyone else.

### How to check what is ignored:
If you want to see exactly what Git is currently ignoring, run:
```bash
git status --ignored
```

---

## Troubleshooting Common Issues

### 1. "Author identity unknown"
If you see this error when committing, Git needs to know who is making the changes. Run these commands locally (replace with your details):

```bash
git config user.email "your.email@example.com"
git config user.name "Your Name"
```

### 2. "Adding embedded git repository: unified_sniffer_agent/vcpkg"
This happens because `vcpkg` has its own `.git` folder. If you want to include all the `vcpkg` files in your main repository (easiest for small projects):

1. **Remove the embedded git tracking**:
   ```bash
   git rm -rf --cached unified_sniffer_agent/vcpkg
   ```
2. **Delete the hidden `.git` folder inside vcpkg**:
   In PowerShell:
   ```powershell
   Remove-Item -Recurse -Force unified_sniffer_agent/vcpkg/.git
   ```
3. **Re-add everything**:
   ```bash
   git add .
   git commit -m "Initial commit of Unified Sniffer Agent project"
   ```

---

## Can others build the sniffer from my repo?

**Yes!** In fact, this is how professional software development works. You share the **source code** (the "recipe") and others compile it themselves.

### What they need:
1.  **The Source Code**: They get this when they `git clone` your repository.
2.  **Tools**: They will need to install CMake and a C++ compiler (like Visual Studio).
3.  **The Setup Scripts**: I included the scripts in `unified_sniffer_agent/installer/` to help them install prerequisites and build the agent.

### Why this is better than uploading the `.exe`:
-   **Security**: People prefer to build from source so they know exactly what the code is doing (no hidden viruses).
-   **Compatibility**: A `.exe` built on your computer might not work on a computer with a different version of Windows or CPU. If they build it themselves, it will be optimized for their machine.
-   **Cleanliness**: Your repository stays small (a few MBs of code) instead of hundreds of MBs of temporary build files.

---

## Updating Your Repository Later

Whenever you make changes and want to update GitHub:

1. `git add .` (Stage changes)
2. `git commit -m "Describe your changes"` (Commit changes)
3. `git push` (Push to GitHub)
