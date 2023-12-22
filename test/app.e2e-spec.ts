import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from './../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { AuthDto } from '../src/auth/dto';
import { Tokens } from '../src/auth/types';

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe());
    await app.init();

    prisma = app.get<PrismaService>(PrismaService);
    await prisma.cleanDatabase();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Auth', () => {
    const dto: AuthDto = {
      email: 'tester@gmail.com',
      password: 'tester123456',
    };

    let tokens: Tokens;

    it('should signup', () => {
      return request(app.getHttpServer())
        .post('/auth/local/signup')
        .send(dto)
        .expect(201)
        .expect(({ body }: { body: Tokens }) => {
          expect(body.accessToken).toBeTruthy();
          expect(body.refreshToken).toBeTruthy();
          expect(body.verifyToken).toBeTruthy();
        });
    });

    it('should signin', () => {
      return request(app.getHttpServer())
        .post('/auth/local/signin')
        .send(dto)
        .expect(200)
        .expect(({ body }: { body: Tokens }) => {
          expect(body.accessToken).toBeTruthy();
          expect(body.refreshToken).toBeTruthy();

          tokens = body;
        });
    });

    it('should refresh tokens', async () => {
      await new Promise((resolve) => {
        setTimeout(() => {
          resolve(true);
        }, 1000);
      });

      return request(app.getHttpServer())
        .post('/auth/refresh')
        .auth(tokens.refreshToken, {
          type: 'bearer',
        })
        .expect(201)
        .expect(({ body }: { body: Tokens }) => {
          expect(body.accessToken).toBeTruthy();
          expect(body.refreshToken).toBeTruthy();

          expect(body.refreshToken).not.toBe(tokens.accessToken);
          expect(body.refreshToken).not.toBe(tokens.refreshToken);
        });
    });

    it('should logout', () => {
      return request(app.getHttpServer())
        .post('/auth/logout')
        .auth(tokens.accessToken, {
          type: 'bearer',
        })
        .expect(204);
    });
  });
});
