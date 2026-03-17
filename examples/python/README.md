# Hive OAuth Example (Python)

Simple OAuth 2.0 example showing how a basic UI connects to Hive's OAuth server and initiates the Authorization Code flow.

## Requirements

Python 3.10+

## Setup

Copy environment file:

    cp .env.example .env

Fill in your Hive OAuth credentials.

## Install

Create and activate a virtual environment:

    cd examples/python
    python3 -m venv .venv
    source .venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

## Run

Start OAuth server:

    python server/app.py

In another terminal:

    cd examples/python
    source .venv/bin/activate
    python -m http.server 3000 --directory ui

## Open

    http://localhost:3000

## Redirect URI

    http://localhost:4000/callback
