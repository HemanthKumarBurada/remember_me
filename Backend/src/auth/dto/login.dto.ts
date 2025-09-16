import { IsEmail, IsNotEmpty, IsString, IsBoolean, IsOptional } from 'class-validator';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsBoolean()
  @IsOptional()
  rememberMe?: boolean;
}