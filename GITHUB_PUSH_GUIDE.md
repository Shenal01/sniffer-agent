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

Copy the remote repository URL from your GitHub repository (it should look like `https://github.com/YOUR_USERNAME/sniffer-agent.git`). Then run:

```bash
git remote add origin https://github.com/YOUR_USERNAME/sniffer-agent.git
```
*(Replace `YOUR_USERNAME` and `sniffer-agent` with your actual GitHub details)*

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

## Updating Your Repository Later

Whenever you make changes and want to update GitHub:

1. `git add .` (Stage changes)
2. `git commit -m "Describe your changes"` (Commit changes)
3. `git push` (Push to GitHub)
