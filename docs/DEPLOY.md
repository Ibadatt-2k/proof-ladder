# Going live: first-time setup

Run everything below in Terminal on your Mac, from inside the `proof-ladder` folder.

## 0. Check it runs locally (5 minutes)

```bash
make install
make demo
make run          # open http://localhost:8080, then Ctrl+C to stop
```

## 1. Push the code to GitHub

1. Go to https://github.com/new
2. Repository name: `proof-ladder`. Public. Do **not** add a README, .gitignore or licence (the repo already has them).
3. Click *Create repository*, then:

```bash
git remote add origin https://github.com/Ibadatt-2k/proof-ladder.git
git push -u origin main
```

GitHub Actions starts automatically. Check the **Actions** tab: the `eval-gate` workflow should go green (tests + evaluation gate). The deploy job is skipped until you set it up in step 4.

## 2. Create a Google Cloud project

```bash
# Install the CLI if `gcloud --version` fails
brew install --cask google-cloud-sdk

gcloud auth login

# Project IDs are global: 6 to 30 characters, lowercase letters, digits and hyphens
export GCP_PROJECT=proof-ladder-ibadatt
gcloud projects create $GCP_PROJECT --name="Proof Ladder"
gcloud config set project $GCP_PROJECT
```

Turn on billing (Cloud Run needs a billing account even when usage stays in the free allowance):

```bash
gcloud billing accounts list                     # copy the ACCOUNT_ID
gcloud billing projects link $GCP_PROJECT --billing-account=ACCOUNT_ID
```

Or do it in the console: https://console.cloud.google.com/billing/linkedaccount

Strongly recommended: set a small budget alert (for example $5) at https://console.cloud.google.com/billing/budgets

Enable the services the deploy uses:

```bash
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com
```

## 3. Deploy

```bash
GCP_PROJECT=$GCP_PROJECT bash deploy/cloudrun.sh
```

- If asked to create an Artifact Registry repository, answer **Y**.
- The build takes a few minutes. The last line printed is your public URL.
- Open it. The first load after idle takes a few extra seconds while it seeds 600 alerts.
- Health check: `<your-url>/api/health`

**If the build fails with a permission error**, grant the build service account the Cloud Run Builder role and deploy again:

```bash
PROJECT_NUMBER=$(gcloud projects describe $GCP_PROJECT --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $GCP_PROJECT \
  --member=serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com \
  --role=roles/run.builder
```

### Cost settings
- Default: scales to zero when nobody is visiting, one instance max. At demo traffic this should stay at or near Cloud Run's free monthly allowance (small Artifact Registry storage may apply).
- `ALWAYS_ON=true` keeps one warm instance with a live alert feed for an interview day. It bills continuously, so turn it off afterwards by redeploying without it.
- `READONLY=true` if you post the link somewhere very public.

## 4. Optional: auto-deploy from GitHub

The workflow deploys `main` automatically once these **repository variables** exist (Settings > Secrets and variables > Actions > Variables): `GCP_PROJECT`, `GCP_WIF_PROVIDER`, `GCP_DEPLOY_SA`. They come from setting up Workload Identity Federation between GitHub and Google Cloud (no keys stored in GitHub). Manual deploys with step 3 are fine for an interview demo.

## 5. Finish
- Put the live URL at the top of the README and on your resume / application.
- Record the 2-minute demo from the README, in case the interviewer's network blocks the link.
