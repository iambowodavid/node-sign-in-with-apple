//Hark code to fetch user information from Apple

const express = require("express");
const AppleAuth = require("apple-auth");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

// The callback route used for Android, which will send the callback parameters from Apple into the Android app.
// This is done using a deeplink, which will cause the Chrome Custom Tab to be dismissed and providing the parameters from Apple back to the app.
app.post("/callbacks/sign_in_with_apple", (request, response) => {
  const redirect = `intent://callback?${new URLSearchParams(
    request.body
  ).toString()}#Intent;package=${
    process.env.ANDROID_PACKAGE_IDENTIFIER
  };scheme=signinwithapple;end`;

  //console.log(`Redirecting to ${redirect}`);

  response.redirect(307, redirect);
});

// Endpoint for the app to login or register with the `code` obtained during Sign in with Apple
// Use this endpoint to exchange the code (which must be validated with Apple within 5 minutes) for a session in your system
app.post("/sign_in_with_apple", async (request, response) => {
  const auth = new AppleAuth(
    {
      // use the bundle ID as client ID for native apps, else use the service ID for web-auth flows
      client_id:
        request.query.useBundleId === "true"
          ? process.env.BUNDLE_ID
          : process.env.SERVICE_ID,
      team_id: process.env.TEAM_ID,
      redirect_uri: process.env.REDIRECT_URL, // does not matter here, as this is already the callback that verifies the token after the redirection
      key_id: process.env.KEY_ID
    },
    process.env.KEY_CONTENTS.replace(/\|/g, "\n"),
    "text"
  );

  //console.log(request.query);

  const accessToken = await auth.accessToken(request.query.code);

  const idToken = jwt.decode(accessToken.id_token);

  const userID = idToken.sub;

  //console.log(idToken);

  //IMPORTANT!!!!!!!!!!!!!!!!!!
  // `userEmail` and `userName` will only be provided for the initial authorization with your app
  //There will be no email or account name again so you have to save these details in the database and use the userID on subsequent logins
  
  //LOGINS TO HARK AFTER THIS WILL NOT HAVE EMAIL OR NAME
  const userEmail = idToken.email;
  const userName = `${request.query.firstName} ${request.query.lastName}`;

  // Save the values provided above to the Hark database, and return to client
  
  response.json({ userData: `${userEmail} / ${userName}` });
});

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});