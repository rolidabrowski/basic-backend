import { ApiProperty } from '@nestjs/swagger';

export class Tokens {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NTc0YTY0NWI5MGY1ZDVkMGE2ZmQ3YjQiLCJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJpYXQiOjE3MDIxNDM1NTcsImV4cCI6MTcwMjE0NDQ1N30.IT-ZVUZ1knYy-1C93SlVuSKsoBWwfBXxHSKt-zR1shc',
    description: 'Access token',
  })
  accessToken: string;

  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NTc0YTY0NWI5MGY1ZDVkMGE2ZmQ3YjQiLCJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJpYXQiOjE3MDIxNDM1NTcsImV4cCI6MTcwMjc0ODM1N30.jWJiCPMvkROdYZAljQmjVZ1tvOrr9DEpvZTb8gbUIok',
    description: 'Refresh token',
  })
  refreshToken: string;

  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NTc0YTY0NWI5MGY1ZDVkMGE2ZmQ3YjQiLCJlbWFpbCI6InVzZXJAbWFpbC5jb20iLCJpYXQiOjE3MDIxNDM1NTcsImV4cCI6MTcwMjE0NDQ1N30.IT-ZVUZ1knYy-1C93SlVuSKsoBWwfBXxHSKt-zR1shc',
    description: 'Verify token',
  })
  verifyToken: string;
}
