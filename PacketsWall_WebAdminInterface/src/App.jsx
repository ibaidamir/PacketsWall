import React, { useState, useEffect } from "react";
import HeroSection from "./components/HeroSection";
import CoreCapabilities from "./components/CoreCapabilities";
import HowItWorks from "./components/HowItWorks";
import TechnicalSpecs from "./components/TechnicalSpecs";
import PerformanceMetrics from "./components/PerformanceMetrics";
import DevelopmentTeam from "./components/DevelopmentTeam";
import Footer from "./components/Footer";
import LiveDashboard from "./components/LiveDashboard";
import "./index.css";

function App() {
  const [activeSection, setActiveSection] = useState('');

  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const offsetTop = element.offsetTop - 80;
      window.scrollTo({
        top: offsetTop,
        behavior: 'smooth'
      });
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      const scrollPosition = window.scrollY + 150;

      if (window.scrollY < 100) {
        setActiveSection('');
        return;
      }

      const sections = ['dashboard', 'protocols', 'settings', 'logs', 'about'];

      for (const section of sections) {
        const element = document.getElementById(section);
        if (element) {
          const offsetTop = element.offsetTop;
          const offsetBottom = offsetTop + element.offsetHeight;

          if (scrollPosition >= offsetTop && scrollPosition < offsetBottom) {
            setActiveSection(section);
            return;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const getLinkClass = (sectionId) => {
    const baseClass = "transition-all duration-300 font-medium px-3 py-2 rounded-lg hover:bg-white/10";
    const colors = {
      about: "text-cyan-400 hover:text-cyan-300",
      dashboard: "text-green-400 hover:text-green-300",
      protocols: "text-blue-400 hover:text-blue-300", 
      settings: "text-orange-400 hover:text-orange-300",
      logs: "text-purple-400 hover:text-purple-300"
    };

    const isActive = activeSection === sectionId;
    const activeClass = isActive ? "bg-white/20 shadow-lg" : "";

    return `${baseClass} ${colors[sectionId]} ${activeClass}`;
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Navigation Bar */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/95 backdrop-blur-md border-b border-gray-800 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <div className="flex items-center space-x-1 cursor-pointer" onClick={() => scrollToSection('about')}>
              <img src="/packetswall-logo-white.png" alt="PacketsWall Logo" className="w-10 h-10" />
              <span className="text-xl font-bold">PacketsWall</span>
            </div>

            {/* Navigation Links */}
            <div className="hidden md:flex space-x-2">
              <button onClick={() => scrollToSection('dashboard')} className={getLinkClass('dashboard')}>
                Monitoring
              </button>
              <button onClick={() => scrollToSection('protocols')} className={getLinkClass('protocols')}>
                Capabilities
              </button>
              <button onClick={() => scrollToSection('settings')} className={getLinkClass('settings')}>
                How It Works
              </button>
              <button onClick={() => scrollToSection('logs')} className={getLinkClass('logs')}>
                Statistics
              </button>
              <button onClick={() => scrollToSection('about')} className={getLinkClass('about')}>
                Team
              </button>
            </div>

            {/* Mobile Menu Button */}
            <div className="md:hidden">
              <button className="text-white hover:text-gray-300">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="pt-16">
        <section className="min-h-screen">
          <HeroSection />
        </section>

        <section id="dashboard" className="min-h-screen bg-gray-900/50">
          <LiveDashboard />
        </section>

        <section id="protocols" className="min-h-screen">
          <CoreCapabilities />
        </section>

        <section id="settings" className="min-h-screen bg-gray-900/50">
          <HowItWorks />
          <TechnicalSpecs />
        </section>
        
        <section id="logs" className="min-h-screen">
          <PerformanceMetrics />
        </section>

        {/* CallToAction Removed */}

        <section id="about" className="min-h-screen">
          <DevelopmentTeam />
        </section>

        <div id="footer">
          <Footer />
        </div>
      </main>
    </div>
  );
}

export default App;
