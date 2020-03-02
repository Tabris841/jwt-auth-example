import { createRefreshToken, createAccessToken } from './auth';
import { hash, compare } from 'bcryptjs';
import { Resolver, Query, Mutation, Arg, ObjectType, Field, Ctx, Int } from 'type-graphql';
import { sign } from 'jsonwebtoken';

import { User } from './entity/User';
import { MyContext } from './MyContext';
import { sendRefreshToken } from './sendRefreshToken';
import { getConnection } from 'typeorm';

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
}

@Resolver()
export class UserResolver {
  @Query(() => [User])
  user() {
    return User.find();
  }

  @Query(() => Boolean)
  async revokeRefreshTokensForUser(@Arg('userId', () => Int) userId: number) {
    await getConnection()
      .getRepository(User)
      .increment({ id: userId }, 'tokenVersion', 1);

    return true;
  }

  @Mutation(() => LoginResponse)
  async login(
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Ctx() { res }: MyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error('could not find user');
    }

    const valid = await compare(password, user.password);

    if (!valid) {
      throw new Error('bad password');
    }

    sendRefreshToken(res, createRefreshToken(user));

    return {
      accessToken: createAccessToken(user)
    };
  }

  @Mutation(() => Boolean)
  async register(@Arg('email') email: string, @Arg('password') password: string) {
    const hashedPassword = await hash(password, 12);

    try {
      await User.insert({ email, password: hashedPassword });
    } catch (err) {
      console.error(err);
      return false;
    }

    return true;
  }
}
