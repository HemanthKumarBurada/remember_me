import React, { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import HeroSection2 from "./HeroSection2";
import HeroSection3 from "./HeroSection3";
import styles from "../styles/HeroContainer.module.css";

// Import HeroSection1 only on client
const HeroSection1 = dynamic(() => import("./HeroSection1"), { ssr: false });

export default function HeroContainer() {
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    <HeroSection1 key={0} />,
    <HeroSection2 key={1} />,
    <HeroSection3 key={2} />,
  ];

  const nextSlide = () =>
    setCurrentSlide((prev) => (prev + 1) % slides.length);

  // Auto-scroll logic
  useEffect(() => {
    const interval = setInterval(() => {
      nextSlide();
    }, 5000); // auto-scroll every 5s

    return () => clearInterval(interval);
  }, []);

  return (
    <div className={styles.heroContainer}>
      {slides[currentSlide]}

      <div className={styles.dotsNav}>
        {slides.map((_, index) => (
          <span
            key={index}
            className={`${styles.dot} ${
              currentSlide === index ? styles.activeDot : ""
            }`}
            onClick={() => setCurrentSlide(index)}
          >
            {currentSlide === index ? "●" : "○"}
          </span>
        ))}
      </div>
    </div>
  );
}