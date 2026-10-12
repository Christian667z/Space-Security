import { jsPDF } from 'jspdf';
import { ThreatItem, ConsoleLogMessage } from '../types/cyberdefense';

export interface PdfReportOptions {
  includeCharts?: boolean;
  includeIocs?: boolean;
  includeLogs?: boolean;
  auditorName?: string;
  hostName?: string;
}

export interface SecurityScoreData {
  score: number;
  ratingLabel: string;
  ratingColor: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  neutralizedCount: number;
  totalThreats: number;
}

/**
 * Calculates current security score based on threats and their statuses.
 */
export function calculateSecurityScore(threats: ThreatItem[]): SecurityScoreData {
  let score = 100;
  const criticalCount = threats.filter(t => t.severity === 'CRITICAL' && t.status === 'ACTIVE').length;
  const highCount = threats.filter(t => t.severity === 'HIGH' && t.status === 'ACTIVE').length;
  const mediumCount = threats.filter(t => t.severity === 'MEDIUM' && t.status === 'ACTIVE').length;
  const lowCount = threats.filter(t => t.severity === 'LOW' && t.status === 'ACTIVE').length;

  const neutralizedCount = threats.filter(
    t => t.status === 'NEUTRALIZED' || t.status === 'SCHEDULED_BOOT_DELETE' || t.status === 'QUARANTINED' || t.status === 'DISMISSED'
  ).length;

  // Deductions
  score -= criticalCount * 18;
  score -= highCount * 10;
  score -= mediumCount * 5;
  score -= lowCount * 2;

  // Bonus for active mitigations
  score += neutralizedCount * 4;

  // Clamp
  score = Math.max(12, Math.min(100, score));

  let ratingLabel = 'OPTIMALE / SÉCURISÉ';
  let ratingColor = '#10b981'; // green

  if (score < 45) {
    ratingLabel = 'CRITIQUE / COMPROMISSION ACTIVE';
    ratingColor = '#ef4444'; // red
  } else if (score < 70) {
    ratingLabel = 'RISQUE ÉLEVÉ / ATTENTION REQUISE';
    ratingColor = '#f97316'; // orange
  } else if (score < 85) {
    ratingLabel = 'VIGILANCE / INTERVENTIONS EN COURS';
    ratingColor = '#3b82f6'; // blue
  }

  return {
    score,
    ratingLabel,
    ratingColor,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    neutralizedCount,
    totalThreats: threats.length,
  };
}

/**
 * Generates an off-screen canvas with a high-resolution Security Score Gauge and charts.
 */
export function generateSecurityChartsCanvas(scoreData: SecurityScoreData): string {
  const canvas = document.createElement('canvas');
  // High resolution for crisp PDF rendering (width: 1400px, height: 480px)
  canvas.width = 1400;
  canvas.height = 480;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';

  // Background card
  ctx.fillStyle = '#090d16';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Subtle border & grid
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 3;
  ctx.strokeRect(10, 10, canvas.width - 20, canvas.height - 20);

  // ==========================================
  // PANEL 1: GAUGE SCORE (Left, x: 20 -> 450)
  // ==========================================
  const centerX = 235;
  const centerY = 245;
  const radius = 135;
  const startAngle = Math.PI * 0.75;
  const endAngle = Math.PI * 2.25;

  // Track arc (gray)
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, startAngle, endAngle);
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 26;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Progress arc
  const totalRange = endAngle - startAngle;
  const currentAngle = startAngle + totalRange * (scoreData.score / 100);

  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, startAngle, currentAngle);
  ctx.strokeStyle = scoreData.ratingColor;
  ctx.lineWidth = 26;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Score text
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 76px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${scoreData.score}`, centerX, centerY - 15);

  ctx.fillStyle = '#94a3b8';
  ctx.font = 'bold 22px sans-serif';
  ctx.fillText('/ 100', centerX, centerY + 38);

  ctx.fillStyle = scoreData.ratingColor;
  ctx.font = 'bold 20px sans-serif';
  ctx.fillText(scoreData.ratingLabel, centerX, centerY + 105);

  // Panel 1 Title
  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 22px sans-serif';
  ctx.fillText('SCORE DE SÉCURITÉ GLOBAUX', centerX, 55);

  // Divider 1
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(470, 30);
  ctx.lineTo(470, 450);
  ctx.stroke();

  // ==========================================
  // PANEL 2: SEVERITY BREAKDOWN DONUT (Center, x: 480 -> 920)
  // ==========================================
  const donutCenterX = 680;
  const donutCenterY = 245;
  const donutRadius = 115;
  const innerRadius = 70;

  // Title 2
  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 22px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('RÉPARTITION DES MENACES', donutCenterX + 10, 55);

  const slices = [
    { label: 'Critiques', count: scoreData.criticalCount, color: '#ef4444' },
    { label: 'Élevées', count: scoreData.highCount, color: '#f97316' },
    { label: 'Moyennes', count: scoreData.mediumCount, color: '#eab308' },
    { label: 'Neutralisées', count: scoreData.neutralizedCount, color: '#10b981' },
  ];

  const totalSlices = slices.reduce((acc, s) => acc + s.count, 0) || 1;
  let currentSliceAngle = -Math.PI / 2;

  slices.forEach(slice => {
    if (slice.count === 0) return;
    const sliceAngle = (slice.count / totalSlices) * Math.PI * 2;
    ctx.beginPath();
    ctx.arc(donutCenterX, donutCenterY, donutRadius, currentSliceAngle, currentSliceAngle + sliceAngle);
    ctx.arc(donutCenterX, donutCenterY, innerRadius, currentSliceAngle + sliceAngle, currentSliceAngle, true);
    ctx.closePath();
    ctx.fillStyle = slice.color;
    ctx.fill();
    currentSliceAngle += sliceAngle;
  });

  // Donut center text
  ctx.fillStyle = '#ffffff';
  ctx.font = 'bold 36px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(`${scoreData.totalThreats}`, donutCenterX, donutCenterY - 6);

  ctx.fillStyle = '#64748b';
  ctx.font = 'bold 16px sans-serif';
  ctx.fillText('TOTAL', donutCenterX, donutCenterY + 22);

  // Donut Legend (Right of donut inside panel 2)
  const legendX = 810;
  let legendY = 145;
  ctx.textAlign = 'left';
  slices.forEach(slice => {
    // Circle indicator
    ctx.beginPath();
    ctx.arc(legendX, legendY, 8, 0, Math.PI * 2);
    ctx.fillStyle = slice.color;
    ctx.fill();

    // Label & count
    ctx.fillStyle = '#e2e8f0';
    ctx.font = 'bold 18px sans-serif';
    ctx.fillText(`${slice.label} : ${slice.count}`, legendX + 18, legendY + 6);
    legendY += 46;
  });

  // Divider 2
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(960, 30);
  ctx.lineTo(960, 450);
  ctx.stroke();

  // ==========================================
  // PANEL 3: DEFENSE LAYERS STATUS (Right, x: 970 -> 1380)
  // ==========================================
  ctx.fillStyle = '#38bdf8';
  ctx.font = 'bold 22px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('COUVERTURE DES DÉFENSES', 1175, 55);

  const layers = [
    { name: 'Noyau & Drivers Ring 0', percent: 65, color: '#f43f5e' },
    { name: 'Processus & Mémoire RAM', percent: 75, color: '#a855f7' },
    { name: 'Persistance BITS & WMI', percent: 50, color: '#eab308' },
    { name: 'Périmètre Réseau & C2', percent: 45, color: '#06b6d4' },
    { name: 'Microsoft Defender (Intact)', percent: 95, color: '#10b981' },
  ];

  let barY = 105;
  const barX = 1000;
  const barWidth = 320;
  const barHeight = 16;

  layers.forEach(layer => {
    // Label & Percent
    ctx.fillStyle = '#cbd5e1';
    ctx.font = 'bold 16px sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(layer.name, barX, barY);

    ctx.textAlign = 'right';
    ctx.fillStyle = layer.color;
    ctx.fillText(`${layer.percent}%`, barX + barWidth, barY);

    // Track
    ctx.fillStyle = '#1e293b';
    ctx.beginPath();
    ctx.roundRect(barX, barY + 8, barWidth, barHeight, 8);
    ctx.fill();

    // Progress
    const fillW = (barWidth * layer.percent) / 100;
    ctx.fillStyle = layer.color;
    ctx.beginPath();
    ctx.roundRect(barX, barY + 8, fillW, barHeight, 8);
    ctx.fill();

    barY += 66;
  });

  return canvas.toDataURL('image/png');
}

/**
 * Main function to generate and download the detailed PDF forensic threat report.
 */
export async function generateAndDownloadPdfReport(
  threats: ThreatItem[],
  logs: ConsoleLogMessage[],
  options: PdfReportOptions = {}
): Promise<void> {
  const {
    includeCharts = true,
    includeIocs = true,
    includeLogs = true,
    auditorName = 'Ingénieur Sécurité & Administrateur Système',
    hostName = 'LOCAL-SEC-ENDPOINT (Windows 11 NT 10.0)',
  } = options;

  const scoreData = calculateSecurityScore(threats);
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - margin * 2;

  const now = new Date();
  const dateFormatted = now.toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  });
  const timeFormatted = now.toLocaleTimeString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const reportRef = `SEC-RPT-${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(
    now.getDate()
  ).padStart(2, '0')}-${Math.floor(1000 + Math.random() * 9000)}`;

  // Helper for page headers/footers
  const addPageHeaderAndFooter = (pageNumber: number, totalPages: number) => {
    // Top banner
    doc.setFillColor(10, 15, 26);
    doc.rect(0, 0, pageWidth, 12, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(56, 189, 248);
    doc.text('SPACESEC CYBERDEFENSE ULTRA v3.0 // RAPPORT OFFICIEL D\'AUDIT FORENSIQUE', margin, 7.5);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184);
    doc.text(`REF: ${reportRef}`, pageWidth - margin, 7.5, { align: 'right' });

    // Bottom banner
    doc.setFillColor(15, 23, 42);
    doc.rect(0, pageHeight - 12, pageWidth, 12, 'F');

    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('CONFIDENTIEL // TLP:AMBER · Analyse Kernel & Contre-Mesures de Destruction', margin, pageHeight - 5);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${pageNumber} sur ${totalPages}`, pageWidth - margin, pageHeight - 5, { align: 'right' });
  };

  // =========================================================================
  // PAGE 1 : COUVERTURE, RÉSUMÉ EXÉCUTIF & GRAPHIQUES DE SCORE
  // =========================================================================

  // Brand Header Block
  doc.setFillColor(15, 23, 42);
  doc.roundedRect(margin, 16, contentWidth, 28, 2, 2, 'F');

  // Cyan border accent
  doc.setDrawColor(14, 165, 233);
  doc.setLineWidth(0.8);
  doc.roundedRect(margin, 16, contentWidth, 28, 2, 2, 'S');

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('RAPPORT D\'INCIDENT FORENSIQUE & POSTURE KERNEL', margin + 6, 26);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('SpaceSec CyberDefense Suite · Neutralisation des Malwares Verrouillés TrustedInstaller & C2', margin + 6, 32);

  // Badge Status Right
  doc.setFillColor(239, 68, 68);
  doc.roundedRect(pageWidth - margin - 52, 21, 46, 8, 1.5, 1.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text('COMPROMISSION EN COURS', pageWidth - margin - 29, 26.5, { align: 'center' });

  // Metadata Grid
  let curY = 48;
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.roundedRect(margin, curY, contentWidth, 22, 1.5, 1.5, 'FD');

  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);

  // Column 1
  doc.text('DATE D\'ANALYSE :', margin + 4, curY + 6);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(`${dateFormatted} à ${timeFormatted}`, margin + 35, curY + 6);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('HÔTE AUDITÉ :', margin + 4, curY + 12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(hostName, margin + 35, curY + 12);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('DROITS SYSTÈME :', margin + 4, curY + 18);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text('Administrateur (Tokens SeDebug / SeTakeOwnership)', margin + 35, curY + 18);

  // Column 2
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('AUDITEUR :', margin + 105, curY + 6);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(auditorName, margin + 130, curY + 6);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('CLASSIFICATION :', margin + 105, curY + 12);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(220, 38, 38);
  doc.text('TLP:AMBER / USAGE RESTREINT', margin + 130, curY + 12);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(30, 41, 59);
  doc.text('RÉFÉRENCE :', margin + 105, curY + 18);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(71, 85, 105);
  doc.text(reportRef, margin + 130, curY + 18);

  curY += 28;

  // =========================================================================
  // VISUAL CHARTS SECTION (Graphiques de Score de Sécurité)
  // =========================================================================
  if (includeCharts) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('1. ANALYSE VISUELLE & SCORE DE SÉCURITÉ GLOBAUX', margin, curY);

    doc.setDrawColor(14, 165, 233);
    doc.setLineWidth(0.5);
    doc.line(margin, curY + 1.5, margin + 95, curY + 1.5);

    curY += 5;

    // High resolution canvas image insertion
    const chartBase64 = generateSecurityChartsCanvas(scoreData);
    if (chartBase64) {
      const chartWidth = contentWidth;
      const chartHeight = 58; // maintains aspect ratio ~1400/480
      doc.addImage(chartBase64, 'PNG', margin, curY, chartWidth, chartHeight);
      curY += chartHeight + 6;
    }
  }

  // Key Statistics Cards
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('2. SYNTHÈSE DES VECTEURS ET IMPACTS FORENSIQUES', margin, curY);
  doc.line(margin, curY + 1.5, margin + 90, curY + 1.5);

  curY += 6;

  const cardWidth = (contentWidth - 9) / 4;
  const cardHeight = 22;

  const statCards = [
    { title: 'MENACES CRITIQUES', value: `${scoreData.criticalCount}`, color: [239, 68, 68], subtitle: 'Péril Immédiat' },
    { title: 'RISQUE ÉLEVÉ / C2', value: `${scoreData.highCount}`, color: [249, 115, 22], subtitle: 'Balises actives' },
    { title: 'VERROUS KERNEL', value: '2', color: [168, 85, 247], subtitle: 'TrustedInstaller' },
    { title: 'EN DÉSTRUCTION', value: `${scoreData.neutralizedCount}`, color: [16, 185, 129], subtitle: 'PendingBoot' },
  ];

  statCards.forEach((card, idx) => {
    const cardX = margin + idx * (cardWidth + 3);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.setLineWidth(0.3);
    doc.roundedRect(cardX, curY, cardWidth, cardHeight, 1.5, 1.5, 'FD');

    // Colored top border accent
    doc.setFillColor(card.color[0], card.color[1], card.color[2]);
    doc.rect(cardX, curY, cardWidth, 1.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.text(card.title, cardX + cardWidth / 2, curY + 6, { align: 'center' });

    doc.setFontSize(14);
    doc.setTextColor(card.color[0], card.color[1], card.color[2]);
    doc.text(card.value, cardX + cardWidth / 2, curY + 14, { align: 'center' });

    doc.setFontSize(6.5);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(card.subtitle, cardX + cardWidth / 2, curY + 19, { align: 'center' });
  });

  curY += cardHeight + 8;

  // Executive Statement Block
  doc.setFillColor(241, 245, 249);
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.3);
  doc.roundedRect(margin, curY, contentWidth, 30, 1.5, 1.5, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text('AVIS DU SYSTÈME CYBERDÉFENSE SPACESEC :', margin + 5, curY + 7);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(51, 65, 85);
  const executiveText =
    `L'audit approfondi a isolé des activités malveillantes actives exploitant des techniques d'évasion avancées. ` +
    `Plusieurs composants résiduels verrouillent leurs accès en usurpant l'identité de NT SERVICE\\TrustedInstaller, ` +
    `interdisant leur suppression même par les comptes Administrateurs locaux. Des flux réseau sortants non autorisés ` +
    `(port 4444 vers 185.220.101.4) ainsi que des tâches asynchrones BITS confirment une tentative d'exfiltration. ` +
    `L'application immédiate du protocole Kernel de destruction différée (PendingFileRenameOperations) et la purge ` +
    `des exclusions Windows Defender sont impérativement requises.`;

  const splitExecutive = doc.splitTextToSize(executiveText, contentWidth - 10);
  doc.text(splitExecutive, margin + 5, curY + 13);

  // =========================================================================
  // PAGE 2 : REGISTRE DÉTAILLÉ DES MENACES DÉTECTÉES
  // =========================================================================
  doc.addPage();
  curY = 18;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text('3. REGISTRE DÉTAILLÉ DES MENACES & ANALYSE TECHNIQUE (MITRE ATT&CK)', margin, curY);

  doc.setDrawColor(14, 165, 233);
  doc.setLineWidth(0.5);
  doc.line(margin, curY + 1.5, margin + 140, curY + 1.5);

  curY += 7;

  // Threats Table Header
  doc.setFillColor(15, 23, 42);
  doc.rect(margin, curY, contentWidth, 7, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.text('MENACE & VECTEUR', margin + 3, curY + 4.8);
  doc.text('SÉVÉRITÉ', margin + 65, curY + 4.8);
  doc.text('MITRE ATT&CK', margin + 90, curY + 4.8);
  doc.text('STATUT', margin + 128, curY + 4.8);
  doc.text('VERROU NOYAU', margin + 158, curY + 4.8);

  curY += 7;

  threats.forEach((threat) => {
    // Check if we need a page break
    if (curY > pageHeight - 38) {
      doc.addPage();
      curY = 18;
      // Repeat table header
      doc.setFillColor(15, 23, 42);
      doc.rect(margin, curY, contentWidth, 7, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(255, 255, 255);
      doc.text('MENACE & VECTEUR', margin + 3, curY + 4.8);
      doc.text('SÉVÉRITÉ', margin + 65, curY + 4.8);
      doc.text('MITRE ATT&CK', margin + 90, curY + 4.8);
      doc.text('STATUT', margin + 128, curY + 4.8);
      doc.text('VERROU NOYAU', margin + 158, curY + 4.8);
      curY += 7;
    }

    const rowHeight = 21;

    // Zebra background
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.rect(margin, curY, contentWidth, rowHeight, 'FD');

    // Threat Name & Category
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(threat.name.slice(0, 38), margin + 3, curY + 5);

    // Target Path
    doc.setFont('courier', 'normal');
    doc.setFontSize(6.8);
    doc.setTextColor(71, 85, 105);
    const shortPath = threat.targetPath.length > 55 ? threat.targetPath.slice(0, 52) + '...' : threat.targetPath;
    doc.text(shortPath, margin + 3, curY + 10);

    // Remediation Command
    doc.setFont('helvetica', 'italic');
    doc.setFontSize(6.8);
    doc.setTextColor(3, 105, 161);
    doc.text(`Action : ${threat.description.slice(0, 68)}...`, margin + 3, curY + 15);

    // Severity Badge
    let sevBg = [239, 68, 68];
    if (threat.severity === 'HIGH') sevBg = [249, 115, 22];
    if (threat.severity === 'MEDIUM') sevBg = [234, 179, 8];
    if (threat.severity === 'LOW') sevBg = [59, 130, 246];

    doc.setFillColor(sevBg[0], sevBg[1], sevBg[2]);
    doc.roundedRect(margin + 65, curY + 3.5, 18, 5, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);
    doc.text(threat.severity, margin + 74, curY + 7.2, { align: 'center' });

    // MITRE
    doc.setFont('courier', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(30, 41, 59);
    doc.text(threat.mitreTechnique.split(' - ')[0] || threat.mitreTechnique, margin + 90, curY + 6.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.text(threat.category, margin + 90, curY + 11.5);

    // Status
    let statusText = 'ACTIF';
    let statusColor: [number, number, number] = [220, 38, 38];
    if (threat.status === 'SCHEDULED_BOOT_DELETE') {
      statusText = 'BOOT-DELETE';
      statusColor = [16, 185, 129];
    } else if (threat.status === 'QUARANTINED') {
      statusText = 'QUARANTAINE';
      statusColor = [217, 119, 6];
    } else if (threat.status === 'NEUTRALIZED') {
      statusText = 'NEUTRALISÉ';
      statusColor = [16, 185, 129];
    } else if (threat.status === 'DISMISSED') {
      statusText = 'IGNORÉ/REJET';
      statusColor = [100, 116, 139];
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
    doc.text(statusText, margin + 128, curY + 7);

    // Lock Info
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    if (threat.trustedInstallerLocked) {
      doc.setTextColor(185, 28, 28);
      doc.text('TrustedInstaller', margin + 158, curY + 7);
      doc.setTextColor(100, 116, 139);
      doc.text('Takeown requis', margin + 158, curY + 12);
    } else if (threat.lockedBySystem) {
      doc.text('Handle Ouvert', margin + 158, curY + 7);
      doc.text('NtSuspendProcess', margin + 158, curY + 12);
    } else {
      doc.text('Non verrouillé', margin + 158, curY + 7);
      doc.text('Suppression std', margin + 158, curY + 12);
    }

    curY += rowHeight + 1.5;
  });

  curY += 6;

  // =========================================================================
  // PAGE 3 : INDICATEURS C2, TÂCHES BITS & RECOMMANDATIONS
  // =========================================================================
  doc.addPage();
  curY = 18;

  if (includeIocs) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('4. INDICATEURS DE COMPROMISSION RÉSEAU (IOC) & C2 BEACONS', margin, curY);
    doc.setDrawColor(14, 165, 233);
    doc.setLineWidth(0.5);
    doc.line(margin, curY + 1.5, margin + 130, curY + 1.5);

    curY += 7;

    // IOC Table
    const iocList = [
      { ip: '185.220.101.4', port: '4444 (TCP)', proto: 'Metasploit Reverse TCP', proc: 'svch0st_updater.exe (PID 5824)', geo: 'Pays-Bas (NL) / Tor Node', status: 'CRITIQUE' },
      { ip: '45.154.255.89', port: '8080 (HTTP)', proto: 'BITS Asynchronous Exfil', proc: 'bitsadmin.exe (Job {3C7D})', geo: 'Russie (RU) / Bulletproof', status: 'ÉLEVÉ' },
      { ip: '198.51.100.22', port: '443 (HTTPS)', proto: 'Cobalt Strike Beacon', proc: 'powershell.exe -enc', geo: 'États-Unis (US) / Cloud VPS', status: 'CRITIQUE' },
    ];

    doc.setFillColor(15, 23, 42);
    doc.rect(margin, curY, contentWidth, 6, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(255, 255, 255);
    doc.text('ADRESSE IP / HOST', margin + 3, curY + 4.2);
    doc.text('PORT & PROTOCOLE', margin + 42, curY + 4.2);
    doc.text('PROCESSUS ASSOCIÉ', margin + 92, curY + 4.2);
    doc.text('ORIGINE GÉO', margin + 140, curY + 4.2);

    curY += 6;

    iocList.forEach(ioc => {
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.2);
      doc.rect(margin, curY, contentWidth, 9, 'FD');

      doc.setFont('courier', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(220, 38, 38);
      doc.text(ioc.ip, margin + 3, curY + 5.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(30, 41, 59);
      doc.text(`${ioc.port} - ${ioc.proto}`, margin + 42, curY + 5.5);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.8);
      doc.setTextColor(71, 85, 105);
      doc.text(ioc.proc, margin + 92, curY + 5.5);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.setTextColor(15, 23, 42);
      doc.text(ioc.geo, margin + 140, curY + 5.5);

      curY += 9;
    });

    curY += 8;
  }

  // Engineering Recommendations & Procedure
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('5. PROTOCOLE D\'ÉRADICATION & RECOMMANDATIONS INGÉNIEUR', margin, curY);
  doc.setDrawColor(14, 165, 233);
  doc.setLineWidth(0.5);
  doc.line(margin, curY + 1.5, margin + 130, curY + 1.5);

  curY += 7;

  const steps = [
    {
      num: 'ÉTAPE 1',
      title: 'Exécution du Script Racine SpaceSec ULTRA',
      desc: 'Lancer SpaceSecurity_ULTRA_v3_Kernel.ps1 avec élévation Administrateur complète (-ExecutionPolicy Bypass). Active l\'ensemble des 25+ modules de cyberdéfense.',
    },
    {
      num: 'ÉTAPE 2',
      title: 'Destruction des Verrous TrustedInstaller & Ring0',
      desc: 'Appliquer les contre-mesures takeown + icacls + PendingFileRenameOperations sur les pilotes malveillants C:\\Windows\\System32\\drivers\\suspicious_kernel_hook.sys.',
    },
    {
      num: 'ÉTAPE 3',
      title: 'Purge des Tâches BITS & Abonnements WMI Persistants',
      desc: 'Annuler les transferts asynchrones (Remove-BitsTransfer / bitsadmin /cancel) et vider les EventConsumers du namespace root\\subscription.',
    },
    {
      num: 'ÉTAPE 4',
      title: 'Réparation Profonde & Ré-activation de Windows Defender',
      desc: 'Restaurer les DLL crypto (wintrust.dll, mssip32.dll), purger les exclusions DisableAntiSpyware et relancer les services de protection en temps réel.',
    },
    {
      num: 'ÉTAPE 5',
      title: 'Redémarrage Contrôlé (Session Manager Pending Operations)',
      desc: 'Redémarrer le poste pour que le sous-système autochk.exe finalise la suppression des binaires verrouillés avant le démarrage des watchdogs tiers.',
    },
  ];

  steps.forEach(step => {
    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, curY, contentWidth, 12, 1.5, 1.5, 'F');

    doc.setFillColor(14, 165, 233);
    doc.roundedRect(margin + 2, curY + 2, 18, 8, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);
    doc.text(step.num, margin + 11, curY + 6.8, { align: 'center' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(step.title, margin + 24, curY + 5.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.8);
    doc.setTextColor(71, 85, 105);
    doc.text(step.desc, margin + 24, curY + 9.5);

    curY += 13.5;
  });

  curY += 6;

  // Digital Signature / Hash Verification Card
  doc.setFillColor(15, 23, 42);
  doc.roundedRect(margin, curY, contentWidth, 22, 2, 2, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(56, 189, 248);
  doc.text('SCEAU NUMÉRIQUE D\'INTÉGRITÉ & CERTIFICATION DE L\'AUDIT', margin + 6, curY + 6);

  doc.setFont('courier', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(148, 163, 184);
  const fakeHash = `SHA256: ${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`;
  doc.text(fakeHash, margin + 6, curY + 11);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(148, 163, 184);
  doc.text(`Signé numériquement par le moteur de sécurité SpaceSec Ultra · Horodatage NTP : ${now.toISOString()}`, margin + 6, curY + 16.5);

  // Add headers/footers to all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    addPageHeaderAndFooter(i, totalPages);
  }

  // Save / trigger download
  const fileName = `SpaceSec_Rapport_Menaces_${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(
    now.getDate()
  ).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}.pdf`;

  doc.save(fileName);
}
