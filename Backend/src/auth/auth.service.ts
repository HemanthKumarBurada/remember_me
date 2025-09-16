import {
  Injectable,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private config: ConfigService,
    private jwtService: JwtService,
  ) {}

  // Updated to accept a dynamic expiration time
  private async signToken(userId: number, email: string, expiresIn: string = '60m'): Promise<string> {
    const payload = { sub: userId, email };
    return this.jwtService.signAsync(payload, { expiresIn });
  }

  async googleLogin(req, res: Response) {
    if (!req.user) {
      throw new BadRequestException('No user from google');
    }

    const { email, firstName, lastName } = req.user;
    const lowerCaseEmail = email.toLowerCase();

    let user = await this.prisma.user.findUnique({ where: { email:lowerCaseEmail } });

    if (!user) {
      const generatedPassword = Math.random().toString(36).slice(-8);
      const hashedPassword = await bcrypt.hash(generatedPassword, 12);

      user = await this.prisma.user.create({
        data: {
          email: lowerCaseEmail,
          fullName: `${firstName} ${lastName}`,
          password: hashedPassword,
        },
      });
    }

    const token = await this.signToken(user.id, user.email, '30d'); // Log in Google users for 30 days by default
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
      path: '/',
    });

    return res.redirect('http://localhost:3000/home');
  }

  // REGISTER
  async register(dto: RegisterDto, res: Response) {
    const { fullName, email, password, confirmPassword } = dto;
    const lowerCaseEmail = email.toLowerCase();
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const existingUser = await this.prisma.user.findUnique({ where: { email:lowerCaseEmail } });
    if (existingUser) {
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: {
        fullName,
        email: lowerCaseEmail,
        password: hashedPassword,
      },
    });
    const token = await this.signToken(user.id, user.email); // Standard 1-hour token
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      expires: new Date(Date.now() + 1000 * 60 * 60), // 1 hour
      path: '/',
    });
    return { message: 'Account created successfully' };
  }

  // LOGIN (with "Remember Me" logic)
  async login(dto: LoginDto, res: Response) {
    const { email, password, rememberMe } = dto;
    const lowerCaseEmail = email.toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email:lowerCaseEmail } });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new BadRequestException('Invalid credentials');
    }

    // Determine the lifetime for both the JWT and the cookie
    const tokenLifetime = rememberMe ? '30d' : '60m'; // 30 days or 60 minutes
    const cookieLifetime = rememberMe
      ? 1000 * 60 * 60 * 24 * 30 // 30 days in milliseconds
      : 1000 * 60 * 60;          // 1 hour in milliseconds

    // Sign the token with the correct lifetime
    const token = await this.signToken(user.id, user.email, tokenLifetime);

    const expires = new Date(Date.now() + cookieLifetime);

    res.cookie('access_token', token, {
      httpOnly: true,
      secure: false, // Set to true in production
      sameSite: 'lax',
      expires: expires,
      path: '/',
    });
    return { message: 'Login successful'};
  }

  // FORGOT PASSWORD or RESEND OTP
  async forgotPassword(dto: ForgotPasswordDto) {
    // ... (existing code is correct)
  }

  // RESET PASSWORD
  async resetPassword(dto: ResetPasswordDto) {
    // ... (existing code is correct)
  }

  // RESEND OTP
  async resendOtp(dto: ForgotPasswordDto) {
    return this.forgotPassword(dto);
  }

  // LOGOUT
  async Logout(res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: false, // Should match login/register methods
      sameSite: 'lax',
      path: '/',
    });
    return {message : 'Logged out sucessfully'}
  }
}