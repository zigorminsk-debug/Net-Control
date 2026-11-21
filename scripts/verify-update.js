'use strict';
// Check that the release metadata really matches the installer and embedded feed.
const fs = require('node:fs');
const crypto = require('node:crypto');
const yaml = require('js-yaml');
const pkg = require('../package.json');
const metadata = yaml.load(fs.readFileSync('dist/latest.yml', 'utf8'));
const feed = yaml.load(fs.readFileSync('dist/win-unpacked/resources/app-update.yml', 'utf8'));
const installer = fs.readFileSync('dist/setup.exe');
const digest = crypto.createHash('sha512').update(installer).digest('base64');
if (metadata.version !== pkg.version) throw new Error(`Incorrect update version: ${metadata.version}`);
if (metadata.path !== 'setup.exe' || metadata.sha512 !== digest) throw new Error('Update metadata does not match setup.exe');
if (!Array.isArray(metadata.files) || !metadata.files.some(file => file.url === 'setup.exe' && file.sha512 === digest && file.size === installer.length)) throw new Error('Update file list does not match setup.exe');
if (feed.provider !== 'github' || feed.owner !== 'zigorminsk-debug' || feed.repo !== 'Net-Control') throw new Error('Incorrect embedded GitHub update feed');
console.log(`Verified GitHub update feed and SHA-512 for ${pkg.version}.`);
