# Bagisto Admin 2FA Implementation

**Mandatory Two-Factor Authentication (2FA) with Google Authenticator for Bagisto Admins**

---

## Overview

This repository provides a step-by-step guide to implement **mandatory 2FA** in a Bagisto (Laravel) admin panel using Google Authenticator.

**Features:**
- Mandatory 2FA for all admin users
- QR code generation & 6-digit OTP verification
- Session security & regeneration
- Rate limiting (5 attempts/min)
- QR code expiration (7 minutes)

---

## Prerequisites

- Bagisto installation (Laravel-based)
- PHP 8.0+
- Composer
- Database access (MySQL/PostgreSQL)
- Basic Laravel knowledge

---

## Installation & Setup

Install required packages:

```bash
composer require pragmarx/google2fa-laravel bacon/bacon-qr-code
php artisan vendor:publish --provider="PragmaRX\Google2FALaravel\ServiceProvider"
