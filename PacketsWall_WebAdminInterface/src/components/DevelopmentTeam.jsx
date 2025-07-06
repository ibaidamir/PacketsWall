import React from "react";

export default function DevelopmentTeam() {
  const team = [
    {
      fullName: "Samer Ataya",
      name: "Security Specialist",
      role: "Cybersecurity Specialist",
      description: "Specialist in network security and DDoS mitigation systems",
      skills: ["Network Security", "DDoS Mitigation", "Threat Analysis"],
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
        </svg>
      )
    },
    {
      fullName: "Amir Ibaid",
      name: "Senior Developer",
      role: "System Architect",
      description: "Specialist in Python systems with experience in networking, design, and cloud integration.",
      skills: ["Python", "Network Programming", "System Design", "Cloud Integration"],
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      fullName: "Nizam Dwikat",
      name: "Data Analyst",
      role: "Security Researcher",
      description: "Specialist in traffic pattern analysis for threat detection",
      skills: ["Data Analysis", "Pattern Recognition"],
      icon: (
        <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      )
    }
  ];

  return (
    <section className="py-20 bg-black">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold mb-4">
            Development <span className="text-blue-400">Team</span>
          </h2>
          <p className="text-xl text-gray-300 max-w-3xl mx-auto">
            Cybersecurity experts and system architects
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {team.map((member, index) => (
            <div
              key={index}
              className="group bg-black rounded-2xl p-8 border border-gray-700 hover:border-blue-500 transition-all duration-300 hover:transform hover:scale-105 text-center"
            >
              {/* Avatar */}
              <div className="w-24 h-24 bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-6 group-hover:bg-blue-600 transition-colors duration-300">
                <div className="text-gray-300 group-hover:text-white transition-colors duration-300">
                  {member.icon}
                </div>
              </div>

              {/* Full Name */}
              <p className="text-lg text-gray-300 font-medium mb-1">{member.fullName}</p>

              {/* Position Title - Made Larger */}
              <h3 className="text-2xl font-semibold text-white mb-2 group-hover:text-blue-400 transition-colors duration-300">
                {member.name}
              </h3>

              {/* Role */}
              <p className="text-blue-400 font-medium mb-4">
                {member.role}
              </p>

              {/* Description */}
              <p className="text-gray-300 mb-6 leading-relaxed">
                {member.description}
              </p>

              {/* Skills */}
              <div className="flex flex-wrap justify-center gap-2">
                {member.skills.map((skill, skillIndex) => (
                  <span
                    key={skillIndex}
                    className="px-3 py-1 bg-gray-700 text-gray-300 rounded-full text-sm font-medium group-hover:bg-blue-900 group-hover:text-blue-300 transition-colors duration-300"
                  >
                    {skill}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
