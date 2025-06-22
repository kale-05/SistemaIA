#!/usr/bin/env bash
gunicorn -w 4 app:app
