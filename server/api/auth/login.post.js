import { getUserByUsername } from "../../db/users";
import bcrypt from "bcrypt";
import { generateTokens, sendRefreshToken } from "~~/server/utils/jwt";
import { userTransformer } from "~~/server/transformers/user";
import { createRefreshToken } from "~~/server/db/refreshTokens";
import { sendError } from "h3";

export default defineEventHandler(async (event) => {
  const body = await readBody(event);

  const { username, password } = body;

  if (!username || !password) {
    return sendError(
      event,
      createError({
        statusCode: 400,
        statusMessage: "Invalid params",
      })
    );
  }

  //Check user register
  const user = await getUserByUsername(username);

  if (!username) {
    return sendError(
      event,
      createError({
        statusCode: 400,
        statusMessage: "Username or password is invalid",
      })
    );
  }

  //Compare passwords
  const doesThePasswordMatch = await bcrypt.compare(password, user.password);

  if (!doesThePasswordMatch) {
    return sendError(
      event,
      createError({
        statusCode: 400,
        statusMessage: "Username or password is invalid",
      })
    );
  }

  //Generate tokens
  //Acces token
  //Refresh token
  const { accessToken, refreshToken } = generateTokens(user);
  //Save it inside db

  await createRefreshToken({
    token: refreshToken,
    userId: user.id,
  });

  //Add http only cookie
  sendRefreshToken(event, refreshToken);

  return {
    accessToken: accessToken,
    user: userTransformer(user),
  };
});
