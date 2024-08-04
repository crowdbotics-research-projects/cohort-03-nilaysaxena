# Assignment Brief

You are being asked to develop a backend for a (simplified) magazine subscription service. This backend service would expose a REST API that enables users to:

1. Register, login, and reset their passwords.
2. Retrieve a list of magazines available for subscription. This list should include the plans available for that magazine and the discount offered for each plan.
3. Create a subscription for a magazine.
4. Retrieve, modify, and delete their subscriptions.

## Model Summary

### Magazine

A magazine that is available for subscription. Includes metadata about the magazine such as the name, description, a base price (for a monthly subscription), and discount - expressed as a decimal - for different subscription plans. The discount for the monthly plan will be set to zero regardless of what is in the discount column in this table. It is possible for a magazine to only offer a subset of plans, in which case the other plans will not be tracked in the database.

### Plan

Plans to which users can subscribe the magazines. The plans contain a title, a description, and a renewal period - expressed in months. Renewal periods CANNOT be zero.

The plans that your backend should have are:

1. Monthly (renewal period = 1 month)
2. Quarterly (renewal period = 3 months)
3. Half-yearly (renewal period = 6 months)
4. Annual (renewal period = 12 months).

### Subscription

A subscription tracks which plan is associated with which magazine for that user. The subscription also tracks the price at renewal for that magazine and the next renewal date. For record keeping purposes, subscriptions are never deleted. If a user cancels a subscription to a magazine, the corresponding `is_active` attribute is set to `False`. Inactive subscriptions are never returned in the response when the user queries their subscriptions.

## Business Rules

1. If a user modifies their subscription for a magazine, the corresponsing subsciption is deactivated and a new subscription is created with a new renewal date depending on the plan that is chosen by the user.
    1. For this purpose assume that there is no proration of the funds and no refunds are issued.