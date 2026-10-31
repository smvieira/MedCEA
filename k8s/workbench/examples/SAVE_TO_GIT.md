# Save your notebooks to git

Your home folder is kept when your server stops, but it is **not backed up**. Keep the work
that matters in the research repository on GitHub, committed under your own name.

The repository is the one your administrator set for this platform. Open a **Terminal**
(File → New → Terminal) and print it:

    echo "$MEDCEA_NOTEBOOK_REPO"

If that prints nothing, ask an administrator which repository to use (for example
`smvieira/medcea-notebooks`) and that you are added to it on GitHub.

## Once: your name, your token, the clone

1. Tell git who you are (the name and e-mail your commits carry):

       git config --global user.name  "Your Name"
       git config --global user.email "you@example.org"

2. Create a **personal access token** on GitHub: Settings → Developer settings → Personal
   access tokens → Fine-grained tokens → Generate new token. Give it access to the research
   repository only, with *Contents: Read and write*, and an expiry date. Copy it.

3. Clone the repository into your home folder (replace OWNER/REPO with what
   `echo "$MEDCEA_NOTEBOOK_REPO"` printed):

       cd ~ && git clone https://github.com/OWNER/REPO.git

   When git asks, the username is your GitHub username and the password is the **token**.
   It is stored in `~/.git-credentials`, in your home only (nobody else's server can read
   it; a hub administrator cannot open your server). Delete that file, or revoke the token
   on GitHub, to take it back.

## Every time: commit and push

1. Save your notebook inside the cloned folder (copy the examples there first; this
   `medcea-examples/` folder is read-only).
2. Open the **Git** panel (the git icon in the left sidebar). Your changed files are under
   *Changed*; click **+** on each one you want to keep (or *Stage all*).
3. Write a short message saying what you changed and click **Commit**.
4. Click the **Push** button (cloud with an arrow up) to send the commits to GitHub.
   **Pull** (arrow down) brings in what colleagues pushed.

## Outputs never leave the platform

Every server has **nbstripout** set up as a git filter: when a notebook is committed, its
cell outputs (tables, charts, printed values) are removed from what git stores. Your
notebook on disk keeps them. So telemetry you read here does not reach GitHub through an
output.

Behind the filter, a check refuses any commit whose notebooks still hold outputs (for
example when a repository turns the filter off, or it could not be installed when your
server started): the commit fails with "Commit refused" and the file names. Clear the
outputs (Edit → Clear Outputs of All Cells), save, stage the file again and commit.

It does not check code or text cells: **do not paste values, tables or tokens into a cell
or a markdown file.** Telemetry is regulated data; you hold read access, not export.

To check what a commit will store, run in the terminal: `git diff --cached`.
