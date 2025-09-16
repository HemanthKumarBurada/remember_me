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

    let user = await this.prisma.user.findUnique({ where: { email: lowerCaseEmail } });

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

    const token = await this.signToken(user.id, user.email, '30d');
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      path: '/',
    });

    return res.redirect('http://localhost:3000/home');
  }

  async register(dto: RegisterDto, res: Response) {
    const { fullName, email, password, confirmPassword } = dto;
    const lowerCaseEmail = email.toLowerCase();
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const existingUser = await this.prisma.user.findUnique({ where: { email: lowerCaseEmail } });
    if (existingUser) {
      throw new BadRequestException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: { fullName, email: lowerCaseEmail, password: hashedPassword },
    });
    const token = await this.signToken(user.id, user.email);
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      expires: new Date(Date.now() + 1000 * 60 * 60),
      path: '/',
    });
    return { message: 'Account created successfully' };
  }

  async login(dto: LoginDto, res: Response) {
    const { email, password, rememberMe } = dto;
    const lowerCaseEmail = email.toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email: lowerCaseEmail } });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new BadRequestException('Invalid credentials');
    }

    const tokenLifetime = rememberMe ? '30d' : '60m';
    const cookieLifetime = rememberMe ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60;
    const token = await this.signToken(user.id, user.email, tokenLifetime);
    const expires = new Date(Date.now() + cookieLifetime);

    res.cookie('access_token', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      expires,
      path: '/',
    });
    return { message: 'Login successful' };
  }

  async forgotPassword(dto: ForgotPasswordDto) {
    const { email } = dto;
    const lowerCaseEmail = email.toLowerCase();

    const user = await this.prisma.user.findUnique({ where: { email: lowerCaseEmail } });
    if (!user) {
      // Security: We throw an error to stop the process, but the frontend
      // should show a generic success message to the user.
      throw new BadRequestException('Email not registered');
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await this.prisma.user.update({
      where: { email: lowerCaseEmail },
      data: { otp, otpExpiry },
    });

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: this.config.get<string>('EMAIL_USER'),
        pass: this.config.get<string>('EMAIL_PASS'),
      },
    });

    await transporter.sendMail({
      from: `"My App" <${this.config.get<string>('EMAIL_USER')}>`,
      to: email,
      subject: 'OTP for Password Reset',
      text: `Your OTP is ${otp}. It will expire in 10 minutes.`,
    });

    return { message: 'An OTP has been sent to your email address.' };
  }

  async resetPassword(dto: ResetPasswordDto) {
    const { email, otp, newPassword, confirmPassword } = dto;
    const lowerCaseEmail = email.toLowerCase();
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    const user = await this.prisma.user.findUnique({ where: { email: lowerCaseEmail } });
    if (!user || user.otp !== otp) {
      throw new BadRequestException('Invalid email or OTP');
    }

    if (!user.otpExpiry || user.otpExpiry < new Date()) {
      throw new BadRequestException('OTP has expired');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await this.prisma.user.update({
      where: { email: lowerCaseEmail },
      data: {
        password: hashedPassword,
        otp: null,
        otpExpiry: null,
      },
    });

    return { message: 'Password reset successful' };
  }

  async resendOtp(dto: ForgotPasswordDto) {
    return this.forgotPassword(dto);
  }

  async Logout(res: Response) {
    res.clearCookie('access_token', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
    });
    return { message: 'Logged out successfully' };
  }
}