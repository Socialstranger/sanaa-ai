
import { hash } from "bcryptjs";
import { NextResponse } from "next/server";

import { prisma } from "@/lib/prisma";

export const runtime = "nodejs";

export async function POST(request: Request) {
  let body: unknown;

  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { success: false, message: "Request body must be valid JSON." },
      { status: 400 },
    );
  }

  if (
    typeof body !== "object" ||
    body === null ||
    !("name" in body) ||
    !("email" in body) ||
    !("password" in body)
  ) {
    return NextResponse.json(
      {
        success: false,
        message: "Name, email, and password are required.",
      },
      { status: 400 },
    );
  }

  const { name, email, password } = body;

  if (
    typeof name !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string"
  ) {
    return NextResponse.json(
      { success: false, message: "Invalid field types." },
      { status: 400 },
    );
  }

  const normalizedName = name.trim();
  const normalizedEmail = email.trim().toLowerCase();

  if (normalizedName.length < 2 || normalizedName.length > 80) {
    return NextResponse.json(
      { success: false, message: "Name must be 2–80 characters." },
      { status: 400 },
    );
  }

  if (
    normalizedEmail.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)
  ) {
    return NextResponse.json(
      { success: false, message: "Enter a valid email address." },
      { status: 400 },
    );
  }

  if (password.length < 8 || password.length > 72) {
    return NextResponse.json(
      {
        success: false,
        message: "Password must be 8–72 characters.",
      },
      { status: 400 },
    );
  }

  try {
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });

    if (existingUser) {
      return NextResponse.json(
        { success: false, message: "An account with this email already exists." },
        { status: 409 },
      );
    }

    const passwordHash = await hash(password, 12);

    const user = await prisma.user.create({
      data: {
        name: normalizedName,
        email: normalizedEmail,
        passwordHash,
      },
      select: {
        id: true,
        name: true,
        email: true,
        createdAt: true,
      },
    });

    return NextResponse.json(
      {
        success: true,
        message: "Account created successfully.",
        user,
      },
      { status: 201 },
    );
  } catch (error) {
    // Protect against two simultaneous requests using the same email.
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "P2002"
    ) {
      return NextResponse.json(
        { success: false, message: "An account with this email already exists." },
        { status: 409 },
      );
    }

    console.error("Artist registration failed.");

    return NextResponse.json(
      { success: false, message: "Unable to create account right now." },
      { status: 500 },
    );
  }
}
