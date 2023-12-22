import {
  BadRequestException,
  ForbiddenException,
  ConflictException,
  InternalServerErrorException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import * as sgMail from '@sendgrid/mail';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import { JwtPayload, Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await argon.hash(dto.password);
    const user = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          hash,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2001') {
            throw new BadRequestException('Invalid data');
          }
          if (error.code === 'P2002') {
            throw new ConflictException('Email already exists');
          }
          if (error.code === 'P5000') {
            throw new InternalServerErrorException('Internal server error');
          }
        }
        throw error;
      });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    await this.updateVtHash(user.id, tokens.verifyToken);
    await this.sendVerifyEmail(user.email, user.hashedVt);
    return tokens;
  }

  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Invalid credentials');

    const passwordMatches = await argon.verify(user.hash, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Invalid credentials');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }

  async logout(userId: string): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
    return true;
  }

  async refreshTokens(userId: string, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatches = await argon.verify(user.hashedRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async updateVtHash(userId: string, vt: string) {
    const hash = await argon.hash(vt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedVt: hash,
      },
    });
  }

  async updateRtHash(userId: string, rt: string) {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getTokens(userId: string, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt, vt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('VT_SECRET'),
        expiresIn: '5m',
      }),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
      verifyToken: vt,
    };
  }

  async sendVerifyEmail(email: string, hashedVt: string): Promise<boolean> {
    sgMail.setApiKey(this.config.get<string>('SENDGRID_API_KEY'));
    const msg = {
      from: this.config.get<string>('SENDGRID_API_EMAIL'),
      to: email,
      subject: 'App - Confirm your email',
      html: `
      <p>Hello, ${email}</p>
      <p>We just need to verify your email address before you can access App.</p>
      <p>Please click on the link below.</p>
      <a href="http://localhost:3000/api/user/verify/${hashedVt}">Click here to verify your email</a>`,
    };

    try {
      await sgMail.send(msg);
    } catch (error) {
      console.error(error);

      if (error.response) {
        console.error(error.response.body);
        throw new InternalServerErrorException('Internal server error');
      }
    }

    return true;
  }
}
