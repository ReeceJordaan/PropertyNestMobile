# PropertyNestMobile

## Overview

Property Nest Mobile is the mobile companion to the Property Nest real estate platform. Built with Angular and Ionic, it provides a native app experience for users to browse property listings, search by location, view agent details, and manage their profile on iOS and Android devices.

## Purpose

This app aims to provide Property Nest users with a seamless and convenient way to access property information and manage their account while on the move.

## App Structure & Features

The application is organized into five main tabs:

1.  **Listings (Tab 1):**
    *   Displays a general feed of the latest property listings (for sale or rent).
    *   Shows key details like title, location, price, bedrooms, bathrooms, and images.
    *   Requires user login to view.
    *   Includes pull-to-refresh functionality.

2.  **Search (Tab 2):**
    *   Provides a dedicated interface for searching property listings specifically by **location**.
    *   Displays listings matching the search criteria.
    *   Remembers the last searched location for convenience.
    *   Requires user login.
    *   Includes pull-to-refresh functionality.

3.  **Profile (Tab 3):**
    *   Displays the logged-in user's name.
    *   Provides a **Logout** button to clear session data and navigate to the Login tab.

4.  **Login (Tab 4):**
    *   Presents the user login form (Email and Password).
    *   Handles user authentication against the backend API.
    *   Stores user credentials (`apikey`, `name`) locally upon successful login.
    *   Redirects to the Listings tab (Tab 1) after login.
    *   Displays error messages for failed login attempts.

5.  **Agents (Tab 5):**
    *   Displays a list of real estate agents associated with the platform.
    *   Fetches agent details and logos from the external Wheatley API.
    *   Requires user login.
    *   Includes pull-to-refresh functionality.

## Tech Stack

### Frontend

*   **Framework:** [Angular](https://angular.io/) (v17)
*   **UI Toolkit:** [Ionic Framework](https://ionicframework.com/) (v8) - For building cross-platform mobile UI.
*   **Native Runtime:** [Capacitor](https://capacitorjs.com/) (v6) - For deploying the web app as a native iOS/Android application.
*   **Language:** [TypeScript](https://www.typescriptlang.org/)
*   **Styling:** SCSS

### Backend

*   **Language:** PHP
*   **Database:** MySQL (Connected via `config.php`)
*   **API Structure:** Object-oriented PHP (`api.php`) handling requests for Users, Listings, and Auctions.

## How It Works

The Ionic/Angular frontend application communicates with the PHP backend API located in the project root. The API handles business logic, interacts with the MySQL database to fetch and store data related to users, properties, and auctions, and returns data to the mobile app in JSON format. Capacitor is used to build and run the application on native mobile platforms (iOS/Android).