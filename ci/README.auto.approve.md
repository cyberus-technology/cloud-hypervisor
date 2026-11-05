# Flake bump auto approve

## Description

We add a github workflow `Flake bump`.
First job of this workflow checks if a merge request contains only one commit which updates the `flake.lock` file.
If this condition is met the second job approve this merge request and automatically merge it.
The approval is done with a dedicated GitHubApp.

## Install

* Follow this guide: https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app
* Create a GitHub app `auto-approve-app` in your GH organization
  * github.com/github-organization/ -> Settings -> Developer Settings -> GitHub Apps -> New GitHub App
    * Add a name and Homepage URL
    * Add Repository Permissions
      * Actions: RO
      * Contents: RW
      * Metadata: RO
      * Pull Requests: RW
      * Workflows: RW

* Install this app into your organization
  * github.com/github-organization/ -> Settings -> Developer Settings -> GitHub Apps -> Select `auto-approve-app` -> Install App
    * Only select repositories:
      * repository-name

* Find app_id
  * github.com/github-organization/ -> Settings -> Developer Settings -> GitHub Apps -> Select `auto-approve-app`
  * you find the app_id in the `General` section

* Create app client secret
  * github.com/github-organization/ -> Settings -> Developer Settings -> GitHub Apps -> Select `auto-approve-app` -> Client secrets
  * The private key will be downloaded using your browser
  * Save it in 1Password or vault

* Create two organization secrets:
  * GH_AUTO_APPROVE_APP_ID
  * GH_AUTO_APPROVE_APP_PRIVATE_KEY

* Add Github App `auto-approve-app` to your branch ruleset.
  * github.com/github-organization/repository -> Settings -> Rules -> Rulesets -> rule name -> Bypass list -> Add bypass
  * This allows the Github App `auto-approve-app` to merge the MRs even if other conditions of the ruleset are not met.
